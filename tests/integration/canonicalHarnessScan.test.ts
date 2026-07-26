import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runScan } from "../../src/core/harness.js";
import type { ScanProgressEvent, ScanRun } from "../../src/shared/types.js";

const fixture = path.resolve(
  "tests/fixtures/research/micro-js-vulnerable",
  "project",
);

test("scanner-only never requires a provider and writes canonical evidence", async () => {
  await withIsolatedHermsecHome(async (root) => {
    process.env.HERMSEC_MODEL_PROVIDER = "openrouter";
    process.env.HERMSEC_MODEL_API_KEY_ENV = "HERMSEC_MISSING_TEST_KEY";
    delete process.env.HERMSEC_MISSING_TEST_KEY;
    const reportRoot = path.join(root, "reports");
    const progress: ScanProgressEvent[] = [];

    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "scanner-only",
      outputDirectory: reportRoot,
      formats: ["json", "html"],
      useModel: true,
      runId: "scanner-only-test",
      onProgress: (event) => progress.push(event),
    });

    assert.equal(result.ok, true);
    if (!result.ok) {
      return;
    }
    const data = result.data as {
      scan: ScanRun;
      report: { summaryPath: string };
    };
    assert.equal(data.scan.id, "scanner-only-test");
    assert.equal(data.scan.assistMode, "scanner-only");
    assert.ok(
      data.scan.terminalStatus === "success" ||
        data.scan.terminalStatus === "partial",
    );
    assert.ok(data.scan.findings.length > 0);
    assert.ok(progress.length > 0);
    assert.ok(
      progress.every(
        (event) =>
          event.runId === "scanner-only-test" &&
          event.assistMode === "scanner-only",
      ),
    );
    const detectorEvidencePath = path.join(
      path.dirname(data.report.summaryPath),
      "detector-evidence.json",
    );
    const detectorEvidence = JSON.parse(
      await fs.readFile(detectorEvidencePath, "utf8"),
    ) as {
      mode: string;
      scannerFindings: unknown[];
      agentFindings: unknown[];
    };
    assert.equal(detectorEvidence.mode, "scanner-only");
    assert.ok(detectorEvidence.scannerFindings.length > 0);
    assert.deepEqual(detectorEvidence.agentFindings, []);
  });
});

test("agent-only fails clearly when model assistance is disabled", async () => {
  await withIsolatedHermsecHome(async (root) => {
    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "single-agent",
      outputDirectory: path.join(root, "reports"),
      formats: ["json"],
      useModel: false,
    });

    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.errorCode, "MODEL_PROVIDER_REQUIRED");
      assert.match(result.message, /requires model assistance/u);
    }
  });
});

test("agent-only reports provider-required when an injected resolver has no model", async () => {
  await withIsolatedHermsecHome(async (root) => {
    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "single-agent",
      outputDirectory: path.join(root, "reports"),
      formats: ["json"],
      useModel: true,
      resolveModel: () => undefined,
    });

    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.errorCode, "MODEL_PROVIDER_REQUIRED");
      assert.match(result.message, /requires an enabled model provider/u);
    }
  });
});

test("hybrid mode preserves scanner evidence when the model path is unavailable", async () => {
  await withIsolatedHermsecHome(async (root) => {
    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "scanner-single",
      outputDirectory: path.join(root, "reports"),
      formats: ["json"],
      useModel: false,
      runId: "hybrid-degraded-test",
    });

    assert.equal(result.ok, true);
    if (!result.ok) {
      return;
    }
    const data = result.data as {
      scan: ScanRun;
      orchestration: {
        mode: string;
        terminalStatus: string;
        scannerFindings: unknown[];
        agentFindings: unknown[];
      };
    };
    assert.equal(data.orchestration.mode, "scanner-single");
    assert.notEqual(data.orchestration.terminalStatus, "success");
    assert.ok(data.orchestration.scannerFindings.length > 0);
    assert.deepEqual(data.orchestration.agentFindings, []);
    assert.ok(data.scan.findings.length > 0);
  });
});

test("cancellation during vulnerability intelligence stops before report generation", async () => {
  await withIsolatedHermsecHome(async (root) => {
    const controller = new AbortController();
    const reportRoot = path.join(root, "reports");
    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "scanner-only",
      outputDirectory: reportRoot,
      formats: ["json"],
      useModel: false,
      signal: controller.signal,
      onProgress: (event) => {
        if (
          event.id === "vulnerability-intelligence" &&
          event.status === "running"
        ) {
          controller.abort(new Error("test cancellation"));
        }
      },
    });

    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.errorCode, "SCAN_CANCELED");
    }
    await assert.rejects(() => fs.access(reportRoot));
  });
});

test("cancellation at report start writes no report artifacts", async () => {
  await withIsolatedHermsecHome(async (root) => {
    const controller = new AbortController();
    const reportRoot = path.join(root, "reports");
    const result = await runScan({
      cwd: fixture,
      target: fixture,
      mode: "offline",
      assistMode: "scanner-only",
      outputDirectory: reportRoot,
      formats: ["json", "html"],
      useModel: false,
      signal: controller.signal,
      onProgress: (event) => {
        if (event.id === "report-ready" && event.status === "running") {
          controller.abort(new Error("stop before report write"));
        }
      },
    });

    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.errorCode, "SCAN_CANCELED");
    }
    await assert.rejects(() => fs.access(reportRoot));
  });
});

async function withIsolatedHermsecHome(
  run: (root: string) => Promise<void>,
): Promise<void> {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-canonical-harness-"),
  );
  const previous = new Map(
    [
      "HERMSEC_HOME",
      "HERMSEC_MODEL_PROVIDER",
      "HERMSEC_MODEL_API_KEY_ENV",
      "HERMSEC_MISSING_TEST_KEY",
    ].map((name) => [name, process.env[name]]),
  );
  try {
    process.env.HERMSEC_HOME = path.join(root, "home");
    await run(root);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
    await fs.rm(root, { recursive: true, force: true });
  }
}
