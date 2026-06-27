import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  MODEL_POLICY,
  buildBenchmarkPlan,
  runBenchmark,
} from "./research-task5-medium-benchmark.mjs";

const repoRoot = path.resolve(import.meta.dirname, "..");

test("medium plan covers the requested scenarios with efficient OpenCode Go models only", () => {
  const plan = buildBenchmarkPlan({ subset: "medium" });
  assert.equal(plan.provider, "opencode-go");
  assert.equal(plan.fixtures.length, 4);
  assert.equal(plan.scenarios.length, 6);
  assert.equal(plan.matrixRuns, 24);
  assert.deepEqual(
    plan.scenarios.map((scenario) => scenario.id),
    ["deep-assisted", "single-agent", "moa-low", "moa-high", "scanner-moa-low", "scanner-moa-high"],
  );

  const allowed = new Set(MODEL_POLICY.allowedModels.map((model) => model.id));
  assert.deepEqual([...allowed].sort(), ["deepseek-v4-flash", "deepseek-v4-pro", "mimo-v2.5", "minimax-m3"]);
  assert.ok(MODEL_POLICY.excludedModels.some((model) => model.id === "gpt-*"));
  for (const scenario of plan.scenarios) {
    assert.equal(scenario.provider, "opencode-go");
    for (const model of scenario.routeModels) {
      assert.ok(allowed.has(model), `${scenario.id} used disallowed model ${model}`);
    }
  }
  const high = plan.scenarios.find((scenario) => scenario.id === "moa-high");
  assert.equal(high?.env?.HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT, "5");
  assert.equal(high?.routeConfig?.moa?.["moa-aggregator"]?.model, "minimax-m3");
});

test("dry-run writes deterministic benchmark artifacts", async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-task5-benchmark-"));
  const outputDir = path.join(tempRoot, "latest");
  const previousKey = process.env.OPENCODE_GO_API_KEY;
  delete process.env.OPENCODE_GO_API_KEY;
  try {
    const result = await runBenchmark({
      repoRoot,
      outDir: outputDir,
      executionMode: "dry-run",
      subset: "smoke",
      generatedAt: "2026-06-27T00:00:00.000Z",
    });

    assert.equal(result.executionMode, "dry-run");
    await assertFile(path.join(outputDir, "metrics.csv"));
    await assertFile(path.join(outputDir, "results.json"));
    await assertFile(path.join(outputDir, "subset-manifest.json"));
    await assertFile(path.join(outputDir, "chart-data.json"));
    await assertFile(path.join(outputDir, "mode-metrics.svg"));
    await assertFile(path.join(outputDir, "mode-counts.svg"));

    const results = JSON.parse(await fs.readFile(path.join(outputDir, "results.json"), "utf8"));
    assert.equal(results.executionMode, "dry-run");
    assert.equal(results.runs.length, 12);
    assert.equal(results.summary.length, 6);
    assert.equal(results.summary[0].scenarioId, "deep-assisted");
    assert.equal(results.summary[0].executionMode, "dry-run");
    assert.equal(results.summary[0].publishable, false);
    assert.equal(results.publicBenchmarks.schemaVersion, "1.0");
    assert.ok(results.publicBenchmarks.suites.some((suite) => suite.id === "owasp-benchmark-java"));

    const csv = await fs.readFile(path.join(outputDir, "metrics.csv"), "utf8");
    assert.match(csv, /^scenario_id,scenario_label,execution_mode,publishable,assist_mode/m);
    assert.match(csv, /deep-assisted,Deep assisted,dry-run,false/);
    assert.match(csv, /scanner-moa-high/);
  } finally {
    if (previousKey === undefined) {
      delete process.env.OPENCODE_GO_API_KEY;
    } else {
      process.env.OPENCODE_GO_API_KEY = previousKey;
    }
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test("dry-run filters scenarios and fixtures consistently across artifacts", async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-task5-filtered-"));
  const outputDir = path.join(tempRoot, "latest");
  const previousKey = process.env.OPENCODE_GO_API_KEY;
  delete process.env.OPENCODE_GO_API_KEY;
  try {
    const result = await runBenchmark({
      repoRoot,
      outDir: outputDir,
      executionMode: "dry-run",
      subset: "medium",
      scenario: "moa-high",
      fixture: "python-flask-vulnerable",
      generatedAt: "2026-06-27T00:00:00.000Z",
    });

    assert.equal(result.summary.length, 1);
    assert.equal(result.summary[0].scenarioId, "moa-high");

    const results = JSON.parse(await fs.readFile(path.join(outputDir, "results.json"), "utf8"));
    assert.deepEqual(results.matrix.map((scenario) => scenario.id), ["moa-high"]);
    assert.deepEqual(results.runs.map((run) => run.runId), ["moa-high__python-flask-vulnerable"]);

    const manifest = JSON.parse(await fs.readFile(path.join(outputDir, "subset-manifest.json"), "utf8"));
    assert.deepEqual(manifest.scenarios.map((scenario) => scenario.id), ["moa-high"]);
    assert.deepEqual(manifest.fixtures.map((fixture) => fixture.id), ["python-flask-vulnerable"]);

    const csv = await fs.readFile(path.join(outputDir, "metrics.csv"), "utf8");
    assert.match(csv, /moa-high,MoA high,dry-run,false/);
    assert.doesNotMatch(csv, /deep-assisted/);
  } finally {
    if (previousKey === undefined) {
      delete process.env.OPENCODE_GO_API_KEY;
    } else {
      process.env.OPENCODE_GO_API_KEY = previousKey;
    }
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

async function assertFile(filePath) {
  const stats = await fs.stat(filePath);
  assert.ok(stats.isFile());
  assert.ok(stats.size > 0);
}
