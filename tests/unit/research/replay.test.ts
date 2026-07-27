import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { ModelRequest, ModelResponse } from "../../../src/model/provider.js";
import {
  fingerprintReplayRequest,
  ReplayCassetteStore,
  ReplayInputRejectedError,
  validateReplayCassette,
} from "../../../src/research/replay.js";

const MODEL = "deepseek/deepseek-v4-flash";

test("secret-bearing raw replay requests are rejected before hashing or persistence", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-secret-"));
  const secret = ["sk", "secret-that-must-never-reach-the-cassette-123456"].join("-");
  const request: ModelRequest = {
    model: MODEL,
    messages: [
      {
        role: "user",
        content: `Authorization: Bearer ${secret}\nAPI_KEY=${secret}`,
      },
    ],
    maxTokens: 100,
  };
  try {
    assert.throws(
      () =>
        fingerprintReplayRequest({
          provider: "openrouter",
          model: MODEL,
          request,
        }),
      ReplayInputRejectedError,
    );
    await assert.rejects(
      () =>
        new ReplayCassetteStore(directory).record({
          provider: "openrouter",
          model: MODEL,
          request,
          response: response("safe"),
        }),
      ReplayInputRejectedError,
    );
    assert.deepEqual(await fs.readdir(directory), []);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("safe request fingerprints remain deterministic and secret response text is redacted", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-redact-"));
  const secret = ["sk", "response-secret-value-1234567890123456"].join("-");
  try {
    const request = safeRequest();
    const reference = await new ReplayCassetteStore(directory).record({
      provider: "openrouter",
      model: MODEL,
      request,
      response: response(`The source contained ${secret}`),
    });
    const raw = await fs.readFile(
      path.join(directory, reference.relativePath),
      "utf8",
    );

    assert.equal(raw.includes(secret), false);
    assert.match(raw, /\[REDACTED\]/);
    assert.equal(
      reference.requestFingerprint,
      fingerprintReplayRequest({
        provider: "openrouter",
        model: MODEL,
        request,
      }),
    );
    assert.equal(
      (
        await validateReplayCassette(
          path.join(directory, reference.relativePath),
        )
      ).integritySha256,
      reference.integritySha256,
    );

    const replayed = await new ReplayCassetteStore(directory, {
      cursorId: "redaction-test",
    }).replay({
      provider: "openrouter",
      model: MODEL,
      request,
    });
    assert.equal(replayed.content.includes(secret), false);
    assert.match(replayed.content, /\[REDACTED\]/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("already-redacted repository assignments can be recorded and replayed", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-placeholder-"),
  );
  const request: ModelRequest = {
    model: MODEL,
    messages: [
      {
        role: "tool",
        toolCallId: "placeholder-tool-call",
        name: "search_code",
        content: [
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_BEGIN",
          '{"preview":"export const fakeFixtureToken = \\"[REDACTED_FOR_MODEL]\\";"}',
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_END",
        ].join("\n"),
      },
    ],
    maxTokens: 100,
  };
  try {
    const recorded = await new ReplayCassetteStore(directory).record({
      provider: "openrouter",
      model: MODEL,
      request,
      response: response("safe"),
    });
    const replayed = await new ReplayCassetteStore(directory, {
      cursorId: "placeholder-test",
    }).replay({
      provider: "openrouter",
      model: MODEL,
      request,
    });

    assert.match(recorded.requestFingerprint, /^[a-f0-9]{64}$/u);
    assert.equal(replayed.content, "safe");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("line-numbered multiline redaction evidence remains replayable", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-multiline-placeholder-"),
  );
  const request: ModelRequest = {
    model: MODEL,
    messages: [
      {
        role: "tool",
        toolCallId: "multiline-placeholder-call",
        name: "read_file_snippet",
        content: [
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_BEGIN",
          JSON.stringify({
            text: [
              "1: export const SERVICE_API_KEY =",
              "[REDACTED_FOR_MODEL]   process.env.SERVICE_API_KEY;",
              "3: ",
            ].join("\n"),
          }),
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_END",
        ].join("\n"),
      },
    ],
    maxTokens: 100,
  };
  try {
    const store = new ReplayCassetteStore(directory);
    const recorded = await store.record({
      provider: "openrouter",
      model: MODEL,
      request,
      response: response("safe"),
    });
    const replayed = await new ReplayCassetteStore(directory, {
      cursorId: "multiline-placeholder-test",
    }).replay({
      provider: "openrouter",
      model: MODEL,
      request,
    });

    assert.match(recorded.requestFingerprint, /^[a-f0-9]{64}$/u);
    assert.equal(replayed.content, "safe");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("marker-substring secrets in JSON-escaped tool evidence remain rejected", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-marker-secret-"),
  );
  const request: ModelRequest = {
    model: MODEL,
    messages: [
      {
        role: "tool",
        toolCallId: "marker-secret-tool-call",
        name: "search_code",
        content: [
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_BEGIN",
          '{"preview":"API_KEY = \\"sk-[REDACTED_FOR_MODEL]-real-secret\\""}',
          "HERMSEC_UNTRUSTED_REPOSITORY_DATA_END",
        ].join("\n"),
      },
    ],
    maxTokens: 100,
  };
  try {
    assert.throws(
      () =>
        fingerprintReplayRequest({
          provider: "openrouter",
          model: MODEL,
          request,
        }),
      ReplayInputRejectedError,
    );
    await assert.rejects(
      () =>
        new ReplayCassetteStore(directory).record({
          provider: "openrouter",
          model: MODEL,
          request,
          response: response("safe"),
        }),
      ReplayInputRejectedError,
    );
    assert.deepEqual(await fs.readdir(directory), []);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("prototype-sensitive own keys remain distinct in replay fingerprints", () => {
  const base = safeRequest();
  const protoA = requestWithOwnKey("__proto__", { variant: "a" });
  const protoB = requestWithOwnKey("__proto__", { variant: "b" });
  const constructor = requestWithOwnKey("constructor", { variant: "a" });
  const fingerprints = [base, protoA, protoB, constructor].map((request) =>
    fingerprintReplayRequest({
      provider: "openrouter",
      model: MODEL,
      request,
    }),
  );

  assert.equal(new Set(fingerprints).size, fingerprints.length);
  assert.equal(
    Object.prototype.hasOwnProperty.call(protoA, "__proto__"),
    true,
  );
  assert.equal(
    (Object.prototype as unknown as Record<string, unknown>).variant,
    undefined,
  );
});

test("record occurrences survive store restarts", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-record-"));
  try {
    const first = await new ReplayCassetteStore(directory).record({
      provider: "openrouter",
      model: MODEL,
      request: safeRequest(),
      response: response("first"),
    });
    const second = await new ReplayCassetteStore(directory).record({
      provider: "openrouter",
      model: MODEL,
      request: safeRequest(),
      response: response("second"),
    });

    assert.equal(first.occurrence, 1);
    assert.equal(second.occurrence, 2);
    assert.notEqual(first.relativePath, second.relativePath);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("replay scopes isolate identical requests across experiment cells", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-scope-"),
  );
  const input = {
    provider: "openrouter" as const,
    model: MODEL,
    request: safeRequest(),
  };
  try {
    const firstScope = new ReplayCassetteStore(directory, {
      scopeId: "fixture-a\u0000moa-low",
    });
    const secondScope = new ReplayCassetteStore(directory, {
      scopeId: "fixture-b\u0000moa-low",
    });
    const firstReference = await firstScope.record({
      ...input,
      response: response("fixture-a"),
    });
    const secondReference = await secondScope.record({
      ...input,
      response: response("fixture-b"),
    });

    assert.equal(firstReference.occurrence, 1);
    assert.equal(secondReference.occurrence, 1);
    assert.notEqual(
      firstReference.requestFingerprint,
      secondReference.requestFingerprint,
    );

    const first = await new ReplayCassetteStore(directory, {
      scopeId: "fixture-a\u0000moa-low",
      cursorId: "replay-run-a",
    }).replay(input);
    const second = await new ReplayCassetteStore(directory, {
      scopeId: "fixture-b\u0000moa-low",
      cursorId: "replay-run-b",
    }).replay(input);
    const repeated = await new ReplayCassetteStore(directory, {
      scopeId: "fixture-a\u0000moa-low",
      cursorId: "second-replay-run-a",
    }).replay(input);

    assert.equal(first.content, "fixture-a");
    assert.equal(second.content, "fixture-b");
    assert.equal(repeated.content, "fixture-a");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

for (const errorCode of ["EPERM", "EBUSY"] as const) {
  test(
    `replay lock recovers from ${errorCode} while initializing owner metadata`,
    { skip: process.platform !== "win32" },
    async () => {
    const directory = await fs.mkdtemp(
      path.join(os.tmpdir(), `hermsec-replay-owner-${errorCode.toLowerCase()}-`),
    );
    const mutableFs = fs as unknown as { writeFile: typeof fs.writeFile };
    const originalWriteFile = mutableFs.writeFile;
    let injected = false;
    mutableFs.writeFile = (async (
      file: Parameters<typeof fs.writeFile>[0],
      data: Parameters<typeof fs.writeFile>[1],
      options?: Parameters<typeof fs.writeFile>[2],
    ) => {
      if (!injected && String(file).endsWith(`${path.sep}owner.json`)) {
        injected = true;
        const error = new Error(
          `Injected ${errorCode} while writing replay lock owner.`,
        ) as NodeJS.ErrnoException;
        error.code = errorCode;
        throw error;
      }
      return originalWriteFile(file, data, options);
    }) as typeof fs.writeFile;

    try {
      const reference = await new ReplayCassetteStore(directory, {
        retryDelayMs: 1,
      }).record({
        provider: "openrouter",
        model: MODEL,
        request: safeRequest(),
        response: response("safe"),
      });

      assert.equal(injected, true);
      assert.equal(reference.occurrence, 1);
      await fs.access(path.join(directory, reference.relativePath));
      await assert.rejects(() => fs.access(path.join(directory, ".replay.lock")));
    } finally {
      mutableFs.writeFile = originalWriteFile;
      await fs.rm(directory, { recursive: true, force: true });
    }
    },
  );
}

test("replay cursors survive restarts and remain isolated by stable cursor ID", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-cursor-"));
  const input = {
    provider: "openrouter" as const,
    model: MODEL,
    request: safeRequest(),
  };
  try {
    const recorder = new ReplayCassetteStore(directory);
    await recorder.record({ ...input, response: response("first") });
    await recorder.record({ ...input, response: response("second") });

    const first = await new ReplayCassetteStore(directory, {
      cursorId: "run-a",
    }).replay(input);
    const second = await new ReplayCassetteStore(directory, {
      cursorId: "run-a",
    }).replay(input);
    const isolated = await new ReplayCassetteStore(directory, {
      cursorId: "run-b",
    }).replay(input);

    assert.equal(first.content, "first");
    assert.equal(second.content, "second");
    assert.equal(isolated.content, "first");
    await assert.rejects(
      () => new ReplayCassetteStore(directory).replay(input),
      /stable cursorId/i,
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("replay cassettes detect tampering", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-tamper-"));
  try {
    const reference = await new ReplayCassetteStore(directory).record({
      provider: "openrouter",
      model: MODEL,
      request: safeRequest(),
      response: response("safe"),
    });
    const cassettePath = path.join(directory, reference.relativePath);
    const raw = await fs.readFile(cassettePath, "utf8");
    await fs.writeFile(cassettePath, raw.replace('"safe"', '"changed"'), "utf8");

    await assert.rejects(
      () => validateReplayCassette(cassettePath),
      /integrity validation failed/i,
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("replay recovery removes only recognized orphan atomic temp files", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-recover-"));
  const orphan = path.join(
    directory,
    `.orphan.json.hermsec-tmp-${randomUUID()}`,
  );
  const unrelated = path.join(directory, ".keep-this-file");
  try {
    await fs.writeFile(orphan, "partial", "utf8");
    await fs.writeFile(unrelated, "keep", "utf8");
    const recovered = await new ReplayCassetteStore(directory).recover();

    assert.equal(recovered, 1);
    await assert.rejects(() => fs.access(orphan));
    assert.equal(await fs.readFile(unrelated, "utf8"), "keep");
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("replay root cannot be a symbolic link or junction", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-replay-link-"));
  const target = path.join(directory, "target");
  const linkedRoot = path.join(directory, "linked");
  try {
    await fs.mkdir(target);
    try {
      await fs.symlink(
        target,
        linkedRoot,
        process.platform === "win32" ? "junction" : "dir",
      );
    } catch (error) {
      if (isNodeError(error) && (error.code === "EPERM" || error.code === "EACCES")) {
        context.skip("This Windows account cannot create a test junction.");
        return;
      }
      throw error;
    }
    await assert.rejects(
      () =>
        new ReplayCassetteStore(linkedRoot).record({
          provider: "openrouter",
          model: MODEL,
          request: safeRequest(),
          response: response("safe"),
        }),
      /real directory|not a link/i,
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

function safeRequest(): ModelRequest {
  return {
    model: MODEL,
    messages: [{ role: "user", content: "Inspect the controlled fixture." }],
    maxTokens: 100,
  };
}

function requestWithOwnKey(key: string, value: unknown): ModelRequest {
  const request = JSON.parse(JSON.stringify(safeRequest())) as Record<
    string,
    unknown
  >;
  Object.defineProperty(request, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
  return request as unknown as ModelRequest;
}

function response(content: string): ModelResponse {
  return {
    content,
    model: MODEL,
    provider: "openrouter",
    usage: {
      provider: "openrouter",
      model: MODEL,
      promptTokens: 20,
      completionTokens: 10,
      totalTokens: 30,
      authoritativeUsd: 0.00001,
      local: false,
    },
  };
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
