import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { classifyExperimentExit } from "./experiment-exit-policy.mjs";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

const execution = oneOf(args.execution ?? "mock", [
  "mock",
  "replay",
  "live",
], "--execution");
const dataset = oneOf(args.dataset ?? "micro", [
  "micro",
  "medium",
  "all",
], "--dataset");
const timestamp = new Date().toISOString().replaceAll(":", "-");
const suiteId =
  args.suiteId ?? `hermsec-seven-mode-${dataset}-${execution}-${timestamp}`;
const suiteDirectory = path.resolve(
  repoRoot,
  args.out ??
    path.join(".hermsec", "research", "runs", `${timestamp}-${dataset}-${execution}`),
);
const replayDirectory = path.resolve(
  repoRoot,
  args.replayDir ??
    path.join(".hermsec", "research", "cassettes", dataset),
);

if (execution === "live") {
  if (!args.allowSpend) {
    fail(
      "Live execution requires --allow-spend. Hermsec still enforces the USD 3.25 global kill switch.",
    );
  }
  if (!process.env.OPENROUTER_API_KEY?.trim()) {
    fail("Live execution requires OPENROUTER_API_KEY in the environment.");
  }
}
if (execution !== "live" && args.allowSpend) {
  fail("--allow-spend is valid only with --execution live.");
}
if (execution === "replay" && !args.replayDir) {
  fail("Replay execution requires an explicit --replay-dir.");
}
if (args.recordCassettes && execution !== "mock") {
  fail("--record-cassettes is valid only with --execution mock.");
}
if (args.recordLiveCassettes && execution !== "live") {
  fail("--record-live-cassettes is valid only with --execution live.");
}

const experimentModule = await importCompiled(
  "dist/src/research/experimentRunner.js",
);
const providerModule = await importCompiled(
  "dist/src/model/openaiCompatible.js",
);
const pricingSnapshot = JSON.parse(
  await fs.readFile(
    path.join(repoRoot, "scripts", "research", "openrouter-pricing.snapshot.json"),
    "utf8",
  ),
);

const result = await experimentModule.runResearchExperiment({
  suiteId,
  suiteDirectory,
  fixtures: fixtureRoots(dataset).map((fixtureRoot) => ({ fixtureRoot })),
  execution,
  provider: providerModule.openRouterProvider,
  pricingSnapshot,
  ...(execution === "replay" ||
  args.recordCassettes ||
  args.recordLiveCassettes
    ? { replayDirectory }
    : {}),
  ...(args.recordCassettes ? { recordMockCassettes: true } : {}),
  ...(args.recordLiveCassettes ? { recordLiveCassettes: true } : {}),
  ...(execution === "live" ? { allowSpend: true } : {}),
});

const exitPolicy = classifyExperimentExit(result);
const summary = {
  suiteId: result.suiteId,
  execution: result.execution,
  dataset,
  suiteDirectory: result.suiteDirectory,
  fixtures: result.fixtureIds.length,
  modes: result.modes.length,
  cells: result.cells.length,
  failedCells: exitPolicy.failedCells.length,
  liveNonSuccessCells: exitPolicy.liveNonSuccessCells.length,
  liveNonSucceededPhysicalModelCalls:
    exitPolicy.liveNonSucceededPhysicalModelCalls.length,
  physicalExecutions: result.physicalExecutions,
  actualPhysicalSpendUsd: result.actualPhysicalSpendUsd,
  conservativeCommittedUsd: result.conservativeCommittedUsd,
  artifacts: result.artifacts,
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);

if (exitPolicy.exitCode !== 0) {
  process.stderr.write(
    result.execution === "live"
      ? `Live experiment failed the paid gate with ${exitPolicy.liveNonSuccessCells.length} non-success cell(s) and ${exitPolicy.liveNonSucceededPhysicalModelCalls.length} non-succeeded physical model call(s).\n`
      : `Experiment completed with ${exitPolicy.failedCells.length} failed or canceled cell(s).\n`,
  );
  process.exitCode = exitPolicy.exitCode;
}

function fixtureRoots(selection) {
  const micro = [
    "tests/fixtures/research/micro-js-vulnerable",
    "tests/fixtures/research/micro-js-clean",
  ];
  const medium = [
    "tests/fixtures/repos/node-express-vulnerable",
    "tests/fixtures/repos/node-express-clean",
    "tests/fixtures/repos/python-flask-vulnerable",
    "tests/fixtures/repos/python-flask-clean",
  ];
  const relativeRoots =
    selection === "micro" ? micro : selection === "medium" ? medium : [...micro, ...medium];
  return relativeRoots.map((relativeRoot) => path.join(repoRoot, relativeRoot));
}

async function importCompiled(relativePath) {
  const modulePath = path.join(repoRoot, relativePath);
  try {
    await fs.access(modulePath);
  } catch {
    fail(
      `Compiled module is missing: ${relativePath}. Run the PMG-wrapped build first.`,
    );
  }
  return import(pathToFileURL(modulePath).href);
}

function parseArgs(values) {
  const parsed = {
    allowSpend: false,
    help: false,
    recordCassettes: false,
    recordLiveCassettes: false,
  };
  const valueFlags = new Map([
    ["--dataset", "dataset"],
    ["--execution", "execution"],
    ["--out", "out"],
    ["--replay-dir", "replayDir"],
    ["--suite-id", "suiteId"],
  ]);
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--allow-spend") {
      parsed.allowSpend = true;
      continue;
    }
    if (value === "--record-cassettes") {
      parsed.recordCassettes = true;
      continue;
    }
    if (value === "--record-live-cassettes") {
      parsed.recordLiveCassettes = true;
      continue;
    }
    if (value === "--help" || value === "-h") {
      parsed.help = true;
      continue;
    }
    const key = valueFlags.get(value);
    if (!key) {
      fail(`Unknown argument: ${value}`);
    }
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      fail(`${value} requires a value.`);
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function oneOf(value, allowed, flag) {
  if (!allowed.includes(value)) {
    fail(`${flag} must be one of: ${allowed.join(", ")}.`);
  }
  return value;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function printHelp() {
  process.stdout.write(`Hermsec seven-mode research experiment

Usage:
  node scripts/research/run-seven-mode-experiment.mjs [options]

Options:
  --execution <mock|replay|live>   Execution backend (default: mock)
  --dataset <micro|medium|all>     Fixture set (default: micro)
  --out <directory>                Fresh immutable suite directory
  --suite-id <id>                  Stable suite identifier
  --replay-dir <directory>         Cassette directory
  --record-cassettes               Record deterministic mock cassettes
  --record-live-cassettes          Record sanitized live cassettes
  --allow-spend                    Required explicit gate for live requests
  --help                           Show this help

All runs score the same seven canonical modes. Hybrid modes reuse the physical
scanner and agent paths and never make additional model calls.
`);
}
