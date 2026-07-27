import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ReplayCassetteStore } from "../../../src/research/replay.js";

const MODEL = "deepseek/deepseek-v4-flash";

test("replay recorder allocates unique occurrences across local processes", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-processes-"),
  );
  try {
    const moduleUrl = new URL(
      "../../../src/research/replay.js",
      import.meta.url,
    ).href;
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        runWorker({
          action: "record",
          moduleUrl,
          directory,
          index,
        }),
      ),
    );
    assert.equal(
      results.every((result) => result.code === 0),
      true,
      results.map(formatResult).join("\n"),
    );
    assert.deepEqual(
      results
        .map((result) => Number(JSON.parse(result.stdout).occurrence))
        .sort((left, right) => left - right),
      Array.from({ length: 10 }, (_, index) => index + 1),
    );
    const cassettes = (await fs.readdir(directory)).filter((name) =>
      name.endsWith(".json"),
    );
    assert.equal(cassettes.length, 10);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("persistent replay cursor serializes concurrent readers without duplicates", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-replay-cursor-processes-"),
  );
  try {
    const store = new ReplayCassetteStore(directory);
    for (let index = 0; index < 6; index += 1) {
      await store.record({
        provider: "openrouter",
        model: MODEL,
        request: request(),
        response: response(`response-${index}`),
      });
    }
    const moduleUrl = new URL(
      "../../../src/research/replay.js",
      import.meta.url,
    ).href;
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, index) =>
        runWorker({
          action: "replay",
          moduleUrl,
          directory,
          index,
          cursorId: "shared-run",
        }),
      ),
    );
    assert.equal(
      results.every((result) => result.code === 0),
      true,
      results.map(formatResult).join("\n"),
    );
    assert.deepEqual(
      results
        .map((result) => JSON.parse(result.stdout).content as string)
        .sort(),
      Array.from({ length: 6 }, (_, index) => `response-${index}`),
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

type WorkerInput = {
  action: "record" | "replay";
  moduleUrl: string;
  directory: string;
  index: number;
  cursorId?: string;
};

type WorkerResult = {
  code: number | null;
  stdout: string;
  stderr: string;
};

function runWorker(input: WorkerInput): Promise<WorkerResult> {
  const code = `
    import { ReplayCassetteStore } from ${JSON.stringify(input.moduleUrl)};
    const store = new ReplayCassetteStore(${JSON.stringify(input.directory)}, {
      ${input.cursorId ? `cursorId: ${JSON.stringify(input.cursorId)},` : ""}
      lockTimeoutMs: 20000,
      retryDelayMs: 5
    });
    const request = ${JSON.stringify(request())};
    ${
      input.action === "record"
        ? `const result = await store.record({
            provider: "openrouter",
            model: ${JSON.stringify(MODEL)},
            request,
            response: ${JSON.stringify(response(`response-${input.index}`))}
          });`
        : `const result = await store.replay({
            provider: "openrouter",
            model: ${JSON.stringify(MODEL)},
            request
          });`
    }
    process.stdout.write(JSON.stringify(result));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", code], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      resolve({ code: exitCode, stdout, stderr });
    });
  });
}

function request() {
  return {
    model: MODEL,
    messages: [{ role: "user" as const, content: "Inspect fixture." }],
    maxTokens: 100,
  };
}

function response(content: string) {
  return {
    content,
    model: MODEL,
    provider: "openrouter" as const,
    usage: {
      provider: "openrouter",
      model: MODEL,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      authoritativeUsd: 0.00001,
      local: false,
    },
  };
}

function formatResult(result: WorkerResult): string {
  return `exit=${result.code} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`;
}
