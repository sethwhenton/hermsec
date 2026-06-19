#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = parseArgs(process.argv.slice(2));
const benchmarkRoot = path.resolve(repoRoot, args.benchmark ?? ".hermsec-benchmarks/BenchmarkJava");
const expectedPath = path.join(benchmarkRoot, "expectedresults-1.2.csv");
const outDir = path.resolve(repoRoot, args.out ?? ".hermsec/evaluation/owasp-benchmark");
const minRecall = numberArg(args["min-recall"], envNumber("HERMSEC_OWASP_MIN_RECALL", 0.8));
const minPrecision = numberArg(args["min-precision"], envNumber("HERMSEC_OWASP_MIN_PRECISION", 0.55));

if (!fs.existsSync(expectedPath)) {
  if (args["skip-if-missing"] === true) {
    console.log(`OWASP BenchmarkJava not found at ${benchmarkRoot}; skipping.`);
    process.exit(0);
  }
  console.error(`OWASP BenchmarkJava expected results not found: ${expectedPath}`);
  process.exit(2);
}

fs.mkdirSync(outDir, { recursive: true });

const { runScan } = await import(pathToFileURL(path.join(repoRoot, "dist/src/core/scan.js")).href);
const scanRun = await runScan({ target: benchmarkRoot, mode: "offline" });
const rawScanPath = path.join(outDir, "benchmark-findings.raw.json");
fs.writeFileSync(rawScanPath, `${JSON.stringify({
  schemaVersion: "1.0",
  scanId: scanRun.id,
  target: scanRun.target,
  generatedAt: scanRun.finishedAt,
  findings: scanRun.findings,
}, null, 2)}\n`, "utf8");

const scoreResult = spawnSync(
  process.execPath,
  [path.join(repoRoot, "scripts/benchmark-java-score.mjs"), expectedPath, rawScanPath],
  { cwd: repoRoot, encoding: "utf8" },
);
if (scoreResult.status !== 0) {
  process.stderr.write(scoreResult.stderr);
  process.exit(scoreResult.status ?? 1);
}

const score = JSON.parse(scoreResult.stdout);
const scorePath = path.join(outDir, "benchmark-score.json");
fs.writeFileSync(scorePath, `${JSON.stringify(score, null, 2)}\n`, "utf8");

const { precision, recall } = score.metrics;
console.log(`OWASP BenchmarkJava: precision ${precision}, recall ${recall}, F1 ${score.metrics.f1}`);
console.log(`Raw findings: ${rawScanPath}`);
console.log(`Score: ${scorePath}`);

if (recall < minRecall || precision < minPrecision) {
  console.error(`OWASP BenchmarkJava gate failed: precision ${precision} < ${minPrecision} or recall ${recall} < ${minRecall}.`);
  process.exit(1);
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) {
      continue;
    }
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = true;
      continue;
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function numberArg(value, fallback) {
  if (typeof value !== "string") {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function envNumber(name, fallback) {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) ? parsed : fallback;
}
