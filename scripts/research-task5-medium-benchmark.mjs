#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO_ROOT = path.resolve(SCRIPT_DIR, "..");
const DEFAULT_OUT_DIR = "docs/research/task5-hermsec-moa/results/latest";
const FIXED_DRY_RUN_AT = "2026-06-27T00:00:00.000Z";
const OPENCODE_GO_API_KEY_ENV = "OPENCODE_GO_API_KEY";
const LOW_SPECIALIST_ROLE_IDS = [
  "injection-and-execution",
  "auth-and-data-flow",
  "secrets-and-config",
];
const HIGH_SPECIALIST_ROLE_IDS = [
  ...LOW_SPECIALIST_ROLE_IDS,
  "database-and-storage",
  "config-and-iac",
];
const JUDGE_AND_AGGREGATOR_ROLE_IDS = [
  "moa-false-positive-judge",
  "moa-aggregator",
];
const LOW_PRODUCT_ROLE_IDS = [...LOW_SPECIALIST_ROLE_IDS, ...JUDGE_AND_AGGREGATOR_ROLE_IDS];
const HIGH_PRODUCT_ROLE_IDS = [...HIGH_SPECIALIST_ROLE_IDS, ...JUDGE_AND_AGGREGATOR_ROLE_IDS];

export const MODEL_POLICY = {
  provider: "opencode-go",
  providerLabel: "OpenCode Go",
  credentialEnv: OPENCODE_GO_API_KEY_ENV,
  allowedModels: [
    { id: "deepseek-v4-flash", origin: "non-US", role: "main specialist and deep-assisted triage model" },
    { id: "mimo-v2.5", origin: "non-US", role: "alternate specialist model for code/context diversity" },
    { id: "deepseek-v4-pro", origin: "non-US", role: "false-positive judge only" },
    { id: "minimax-m3", origin: "non-US", role: "final aggregator model" },
  ],
  excludedModels: [
    { id: "gpt-*", reason: "US flagship family excluded by the experiment policy." },
    { id: "claude-*", reason: "US flagship family excluded by the experiment policy." },
    { id: "gemini-*", reason: "US flagship family excluded by the experiment policy." },
    { id: "grok-*", reason: "US flagship family excluded by the experiment policy." },
    { id: "llama-*", reason: "US flagship family excluded by the experiment policy." },
  ],
};

const FIXTURE_DEFINITIONS = [
  {
    id: "node-express-vulnerable",
    relativePath: "tests/fixtures/repos/node-express-vulnerable",
    language: ["javascript"],
    framework: ["express"],
  },
  {
    id: "node-express-clean",
    relativePath: "tests/fixtures/repos/node-express-clean",
    language: ["javascript"],
    framework: ["express"],
  },
  {
    id: "python-flask-vulnerable",
    relativePath: "tests/fixtures/repos/python-flask-vulnerable",
    language: ["python"],
    framework: ["flask"],
  },
  {
    id: "python-flask-clean",
    relativePath: "tests/fixtures/repos/python-flask-clean",
    language: ["python"],
    framework: ["flask"],
  },
];

const SCENARIOS = [
  {
    id: "deep-assisted",
    label: "Deep assisted",
    assistMode: "deep-assisted",
    modelTier: "efficient-default",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: true,
    routeModels: ["deepseek-v4-flash"],
    env: {
      HERMSEC_MODEL_CHUNK_SIZE: "10",
      HERMSEC_MODEL_CHUNK_TIMEOUT_MS: "60000",
      HERMSEC_MODEL_SUMMARY_WATCHDOG_MS: "180000",
    },
  },
  {
    id: "single-agent",
    label: "Single agent",
    assistMode: "single-agent",
    modelTier: "efficient-default",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: false,
    routeModels: ["deepseek-v4-flash"],
    routeConfig: {
      singleAgent: route("deepseek-v4-flash"),
    },
    env: {
      HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "1",
      HERMSEC_PRODUCT_AGENT_PANEL: "single",
    },
  },
  {
    id: "moa-low",
    label: "MoA low",
    assistMode: "moa-assisted",
    modelTier: "low",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: false,
    routeModels: ["deepseek-v4-flash", "mimo-v2.5", "deepseek-v4-pro", "minimax-m3"],
    routeConfig: {
      moa: {
        "injection-and-execution": route("deepseek-v4-flash"),
        "auth-and-data-flow": route("mimo-v2.5"),
        "secrets-and-config": route("deepseek-v4-flash"),
        "moa-false-positive-judge": route("deepseek-v4-pro"),
        "moa-aggregator": route("minimax-m3"),
      },
    },
    env: {
      HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "3",
      HERMSEC_PRODUCT_AGENT_PANEL: "low",
      HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT: "60",
    },
  },
  {
    id: "moa-high",
    label: "MoA high",
    assistMode: "moa-assisted",
    modelTier: "high",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: false,
    routeModels: ["deepseek-v4-flash", "mimo-v2.5", "deepseek-v4-pro", "minimax-m3"],
    routeConfig: {
      moa: {
        "injection-and-execution": route("deepseek-v4-flash"),
        "auth-and-data-flow": route("mimo-v2.5"),
        "secrets-and-config": route("deepseek-v4-flash"),
        "database-and-storage": route("mimo-v2.5"),
        "config-and-iac": route("deepseek-v4-flash"),
        "moa-false-positive-judge": route("deepseek-v4-pro"),
        "moa-aggregator": route("minimax-m3"),
      },
    },
    env: {
      HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "5",
      HERMSEC_PRODUCT_AGENT_PANEL: "high",
      HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT: "120",
    },
  },
  {
    id: "scanner-moa-low",
    label: "Scanner+MoA low",
    assistMode: "scanner-moa-assisted",
    modelTier: "low",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: true,
    routeModels: ["deepseek-v4-flash", "mimo-v2.5", "deepseek-v4-pro", "minimax-m3"],
    routeConfig: {
      moa: {
        "injection-and-execution": route("deepseek-v4-flash"),
        "auth-and-data-flow": route("mimo-v2.5"),
        "secrets-and-config": route("deepseek-v4-flash"),
        "moa-false-positive-judge": route("deepseek-v4-pro"),
        "moa-aggregator": route("minimax-m3"),
      },
    },
    env: {
      HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "3",
      HERMSEC_PRODUCT_AGENT_PANEL: "low",
      HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT: "60",
      HERMSEC_SCANNER_MOA_SCANNER_CANDIDATE_LIMIT: "80",
    },
  },
  {
    id: "scanner-moa-high",
    label: "Scanner+MoA high",
    assistMode: "scanner-moa-assisted",
    modelTier: "high",
    defaultModel: "deepseek-v4-flash",
    scannerBacked: true,
    routeModels: ["deepseek-v4-flash", "mimo-v2.5", "deepseek-v4-pro", "minimax-m3"],
    routeConfig: {
      moa: {
        "injection-and-execution": route("deepseek-v4-flash"),
        "auth-and-data-flow": route("mimo-v2.5"),
        "secrets-and-config": route("deepseek-v4-flash"),
        "database-and-storage": route("mimo-v2.5"),
        "config-and-iac": route("deepseek-v4-flash"),
        "moa-false-positive-judge": route("deepseek-v4-pro"),
        "moa-aggregator": route("minimax-m3"),
      },
    },
    env: {
      HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "5",
      HERMSEC_PRODUCT_AGENT_PANEL: "high",
      HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT: "120",
      HERMSEC_SCANNER_MOA_SCANNER_CANDIDATE_LIMIT: "120",
    },
  },
];

const DRY_RUN_PROFILES = {
  "deep-assisted": { hitRate: 0.67, falsePositivesVulnerable: 2, falsePositivesClean: 1, durationMs: 65_000 },
  "single-agent": { hitRate: 0.25, falsePositivesVulnerable: 0, falsePositivesClean: 0, durationMs: 12_000 },
  "moa-low": { hitRate: 0.42, falsePositivesVulnerable: 1, falsePositivesClean: 0, durationMs: 58_000 },
  "moa-high": { hitRate: 0.67, falsePositivesVulnerable: 1, falsePositivesClean: 0, durationMs: 86_000 },
  "scanner-moa-low": { hitRate: 0.67, falsePositivesVulnerable: 2, falsePositivesClean: 1, durationMs: 82_000 },
  "scanner-moa-high": { hitRate: 0.83, falsePositivesVulnerable: 1, falsePositivesClean: 0, durationMs: 105_000 },
};

function route(model) {
  return {
    provider: MODEL_POLICY.provider,
    model,
    apiKeyEnv: OPENCODE_GO_API_KEY_ENV,
    allowRemoteProviders: true,
  };
}

export function buildBenchmarkPlan(options = {}) {
  const subset = options.subset ?? "medium";
  const fixtures = selectFixtureDefinitions(subset, options.fixture);
  const scenarios = selectScenarios(options.scenario);
  return {
    schemaVersion: "1.0",
    subset,
    provider: MODEL_POLICY.provider,
    modelPolicy: MODEL_POLICY,
    fixtures: fixtures.map((fixture) => ({ ...fixture })),
    scenarios: scenarios.map((scenario) => publicScenario(scenario)),
    matrixRuns: fixtures.length * scenarios.length,
  };
}

export async function runBenchmark(options = {}) {
  const repoRoot = path.resolve(options.repoRoot ?? DEFAULT_REPO_ROOT);
  const outDir = path.resolve(repoRoot, options.outDir ?? DEFAULT_OUT_DIR);
  const subset = options.subset ?? "medium";
  const requestedMode = options.executionMode ?? "auto";
  const credential = await resolveOpenCodeGoCredential({ ...options, repoRoot });
  const keyAvailable = credential.present;
  const executionMode = requestedMode === "auto"
    ? keyAvailable ? "actual" : "dry-run"
    : requestedMode;
  if (executionMode === "actual" && !keyAvailable) {
    throw new Error(`${OPENCODE_GO_API_KEY_ENV} is required for --actual network benchmark runs.`);
  }

  const generatedAt = options.generatedAt ?? (executionMode === "dry-run" ? FIXED_DRY_RUN_AT : new Date().toISOString());
  const fixtures = await loadFixtures(repoRoot, subset, options.fixture);
  const scenarios = selectScenarios(options.scenario);
  const publicBenchmarks = await buildPublicBenchmarkManifest(repoRoot, generatedAt);
  const manifest = buildSubsetManifest({ subset, fixtures, scenarios, generatedAt, publicBenchmarks });
  const warnings = [];
  if (executionMode === "dry-run") {
    warnings.push(`${OPENCODE_GO_API_KEY_ENV} was unavailable or --dry-run was requested; generated deterministic smoke data without network calls.`);
  }

  await prepareOutputDirectory(outDir);
  if (executionMode === "actual" && options.build !== false) {
    buildCore(repoRoot);
  }

  const runs = [];
  for (const scenario of scenarios) {
    for (const fixture of fixtures) {
      const run = executionMode === "dry-run"
        ? await runDryRun({ repoRoot, outDir, scenario, fixture, generatedAt })
        : await runActual({ repoRoot, outDir, scenario, fixture, timeoutMs: options.timeoutMs });
      runs.push(run);
    }
  }

  const summary = aggregateRuns(runs, executionMode, scenarios);
  const results = {
    schemaVersion: "1.0",
    generatedAt,
    executionMode,
    subset,
    outputRoot: toRepoRelativePath(repoRoot, outDir),
    provider: MODEL_POLICY.provider,
    modelPolicy: MODEL_POLICY,
    credentialSource: credential.source,
    git: readGitMetadata(repoRoot),
    warnings,
    matrix: scenarios.map((scenario) => publicScenario(scenario)),
    publicBenchmarks,
    summary,
    runs,
  };
  const chartData = buildChartData({ generatedAt, subset, executionMode, summary });
  const metricsCsv = renderMetricsCsv(summary);
  const charts = renderChartSvgs(summary);

  await fs.writeFile(path.join(outDir, "subset-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await fs.writeFile(path.join(outDir, "results.json"), `${JSON.stringify(results, null, 2)}\n`, "utf8");
  await fs.writeFile(path.join(outDir, "chart-data.json"), `${JSON.stringify(chartData, null, 2)}\n`, "utf8");
  await fs.writeFile(path.join(outDir, "metrics.csv"), metricsCsv, "utf8");
  await fs.writeFile(path.join(outDir, "mode-metrics.svg"), charts.metrics, "utf8");
  await fs.writeFile(path.join(outDir, "mode-counts.svg"), charts.counts, "utf8");
  await fs.writeFile(path.join(outDir, "README.md"), renderResultsReadme({ executionMode, subset, generatedAt }), "utf8");

  return {
    executionMode,
    outDir,
    resultsPath: path.join(outDir, "results.json"),
    metricsPath: path.join(outDir, "metrics.csv"),
    manifestPath: path.join(outDir, "subset-manifest.json"),
    chartDataPath: path.join(outDir, "chart-data.json"),
    chartPaths: {
      metrics: path.join(outDir, "mode-metrics.svg"),
      counts: path.join(outDir, "mode-counts.svg"),
    },
    summary,
  };
}

async function resolveOpenCodeGoCredential(options = {}) {
  if (process.env[OPENCODE_GO_API_KEY_ENV]?.trim()) {
    return { present: true, source: "environment" };
  }
  const localEnvKey = await readLocalEnvKey(options.repoRoot);
  if (localEnvKey) {
    process.env[OPENCODE_GO_API_KEY_ENV] = localEnvKey;
    return { present: true, source: ".env.local" };
  }
  if (options.desktopSettings === false) {
    return { present: false, source: "missing" };
  }
  const key = await readDesktopOpenCodeGoKey();
  if (key) {
    process.env[OPENCODE_GO_API_KEY_ENV] = key;
    return { present: true, source: "desktop-settings" };
  }
  return { present: false, source: "missing" };
}

async function readLocalEnvKey(repoRoot) {
  if (!repoRoot) {
    return undefined;
  }
  try {
    const envText = await fs.readFile(path.join(repoRoot, ".env.local"), "utf8");
    for (const line of envText.split(/\r?\n/u)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }
      const match = /^OPENCODE_GO_API_KEY\s*=\s*(.+)$/u.exec(trimmed);
      if (!match) {
        continue;
      }
      const value = match[1].trim().replace(/^['"]|['"]$/gu, "");
      if (value) {
        return value;
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function readDesktopOpenCodeGoKey() {
  const appData = process.env.APPDATA;
  if (!appData) {
    return undefined;
  }
  const candidates = [
    path.join(appData, "hermsec-v3", "settings.json"),
    path.join(appData, "Hermsec", "settings.json"),
  ];
  for (const filePath of candidates) {
    try {
      const settings = JSON.parse(await fs.readFile(filePath, "utf8"));
      const provider = Array.isArray(settings.providers)
        ? settings.providers.find((item) => item?.id === MODEL_POLICY.provider && item?.enabled !== false)
        : undefined;
      if (typeof provider?.apiKey === "string" && provider.apiKey.trim()) {
        return provider.apiKey.trim();
      }
    } catch {
      // Settings are optional for CLI research runs.
    }
  }
  return undefined;
}

async function loadFixtures(repoRoot, subset, fixtureFilter) {
  const definitions = selectFixtureDefinitions(subset, fixtureFilter);
  return Promise.all(definitions.map(async (definition) => {
    const fixtureRoot = path.resolve(repoRoot, definition.relativePath);
    const groundTruth = await parseFixtureGroundTruth(path.join(fixtureRoot, "groundtruth.yml"));
    return {
      ...definition,
      path: definition.relativePath,
      absolutePath: fixtureRoot,
      kind: groundTruth.kind,
      safeToRun: groundTruth.safeToRun,
      expectedFindings: groundTruth.expectedFindings,
      expectedFindingCount: groundTruth.expectedFindings.length,
    };
  }));
}

async function buildPublicBenchmarkManifest(repoRoot, generatedAt) {
  return {
    schemaVersion: "1.0",
    generatedAt,
    note: "Public benchmark chunks are prepared for the publishable actual run. The controlled fixture matrix remains the local smoke/scoring harness until model-backed public-suite execution is enabled.",
    suites: [
      await benchmarkJavaSubset(repoRoot),
      await openSsfCveSubset(repoRoot),
      await castleSubset(repoRoot),
      await julietSubset(repoRoot),
    ],
  };
}

async function benchmarkJavaSubset(repoRoot) {
  const csvPath = path.join(repoRoot, ".hermsec-benchmarks", "BenchmarkJava", "expectedresults-1.2.csv");
  try {
    const rows = (await fs.readFile(csvPath, "utf8"))
      .split(/\r?\n/)
      .filter((line) => line.trim() && !line.startsWith("#"))
      .map((line) => {
        const [testName, category, vulnerable, cwe] = line.split(",");
        return { testName, category, vulnerable: vulnerable === "true", cwe: `CWE-${cwe}` };
      });
    const categories = ["sqli", "xss", "cmdi", "pathtraver", "ldapi", "xpathi", "crypto", "hash", "weakrand"];
    const selected = [];
    for (const category of categories) {
      selected.push(...rows.filter((row) => row.category === category && row.vulnerable).slice(0, 3));
      selected.push(...rows.filter((row) => row.category === category && !row.vulnerable).slice(0, 2));
    }
    return {
      id: "owasp-benchmark-java",
      label: "OWASP BenchmarkJava",
      status: "available",
      source: "OWASP-Benchmark/BenchmarkJava",
      localPath: ".hermsec-benchmarks/BenchmarkJava",
      selection: "Up to 3 vulnerable and 2 safe cases per selected Java category.",
      selectedCaseCount: selected.length,
      categories,
      cases: selected,
    };
  } catch {
    return missingBenchmark("owasp-benchmark-java", "OWASP BenchmarkJava", ".hermsec-benchmarks/BenchmarkJava");
  }
}

async function openSsfCveSubset(repoRoot) {
  const cveDir = path.join(repoRoot, ".hermsec-benchmarks", "ossf-cve-benchmark", "CVEs");
  try {
    const files = (await fs.readdir(cveDir))
      .filter((name) => /^CVE-.*\.json$/i.test(name))
      .sort()
      .slice(0, 20);
    const cases = [];
    for (const file of files) {
      const raw = JSON.parse(await fs.readFile(path.join(cveDir, file), "utf8"));
      cases.push({
        cve: raw.CVE,
        repository: raw.repository,
        cwes: raw.CWEs ?? [],
        prePatchFile: raw.prePatch?.weaknesses?.[0]?.location?.file,
        prePatchLine: raw.prePatch?.weaknesses?.[0]?.location?.line,
      });
    }
    return {
      id: "openssf-cve-benchmark",
      label: "OpenSSF CVE Benchmark",
      status: "available",
      source: "ossf-cve-benchmark/ossf-cve-benchmark",
      localPath: ".hermsec-benchmarks/ossf-cve-benchmark",
      selection: "First 20 CVE descriptors from the shallow clone, preserving vulnerable repository metadata.",
      selectedCaseCount: cases.length,
      cases,
    };
  } catch {
    return missingBenchmark("openssf-cve-benchmark", "OpenSSF CVE Benchmark", ".hermsec-benchmarks/ossf-cve-benchmark");
  }
}

async function castleSubset(repoRoot) {
  const jsonPath = path.join(repoRoot, ".hermsec-benchmarks", "CASTLE-Benchmark", "datasets", "CASTLE-C250.min.json");
  try {
    const dataset = JSON.parse(await fs.readFile(jsonPath, "utf8"));
    const tests = Array.isArray(dataset.tests) ? dataset.tests : [];
    const cwes = [22, 78, 89, 125, 134, 190, 327, 416, 787];
    const cases = [];
    for (const cwe of cwes) {
      cases.push(...tests.filter((test) => test.cwe === cwe && test.vulnerable === true).slice(0, 2));
      cases.push(...tests.filter((test) => test.cwe === cwe && test.vulnerable === false).slice(0, 1));
    }
    return {
      id: "castle-c250",
      label: "CASTLE C250",
      status: "available",
      source: "CASTLE-Benchmark/CASTLE-Benchmark",
      localPath: ".hermsec-benchmarks/CASTLE-Benchmark",
      selection: "Up to 2 vulnerable and 1 safe C program per selected CWE.",
      selectedCaseCount: cases.length,
      cwes: cwes.map((cwe) => `CWE-${cwe}`),
      cases: cases.map((test) => ({
        name: test.name,
        vulnerable: Boolean(test.vulnerable),
        cwe: `CWE-${test.cwe}`,
        lines: test.lines ?? [],
        description: test.description,
      })),
    };
  } catch {
    return missingBenchmark("castle-c250", "CASTLE C250", ".hermsec-benchmarks/CASTLE-Benchmark");
  }
}

async function julietSubset(repoRoot) {
  const julietPath = path.join(repoRoot, ".hermsec-benchmarks", "Juliet");
  try {
    await fs.access(julietPath);
    return {
      id: "nist-juliet-subset",
      label: "NIST Juliet subset",
      status: "available",
      source: "NIST Juliet 1.1 C/C++ and Java",
      localPath: ".hermsec-benchmarks/Juliet",
      selection: "Selected Java/C/C++ good/bad pairs. Exact files are resolved by the actual-run preparer.",
      selectedCaseCount: 0,
      cases: [],
    };
  } catch {
    return {
      ...missingBenchmark("nist-juliet-subset", "NIST Juliet subset", ".hermsec-benchmarks/Juliet"),
      source: "NIST Juliet 1.1 C/C++ and Java",
      selection: "Not downloaded locally; keep as planned expansion unless the suite is added to the ignored benchmark cache.",
    };
  }
}

function missingBenchmark(id, label, localPath) {
  return {
    id,
    label,
    status: "missing",
    localPath,
    selectedCaseCount: 0,
    cases: [],
  };
}

function selectFixtureDefinitions(subset, fixtureFilter) {
  const filter = toFilterSet(fixtureFilter);
  const applyFilter = (items) => {
    const filtered = filter ? items.filter((fixture) => filter.has(fixture.id)) : items;
    if (filtered.length === 0) {
      throw new Error(`No fixtures matched "${fixtureFilter}". Available fixtures: ${FIXTURE_DEFINITIONS.map((fixture) => fixture.id).join(", ")}.`);
    }
    return filtered;
  };
  if (subset === "smoke") {
    return applyFilter(FIXTURE_DEFINITIONS.slice(0, 2));
  }
  if (subset === "vulnerable-only") {
    return applyFilter(FIXTURE_DEFINITIONS.filter((fixture) => fixture.id.endsWith("-vulnerable")));
  }
  if (subset !== "medium") {
    throw new Error(`Unknown subset "${subset}". Use medium, smoke, or vulnerable-only.`);
  }
  return applyFilter(FIXTURE_DEFINITIONS);
}

function selectScenarios(scenarioFilter) {
  const filter = toFilterSet(scenarioFilter);
  const scenarios = filter ? SCENARIOS.filter((scenario) => filter.has(scenario.id)) : SCENARIOS;
  if (scenarios.length === 0) {
    throw new Error(`No scenarios matched "${scenarioFilter}". Available scenarios: ${SCENARIOS.map((scenario) => scenario.id).join(", ")}.`);
  }
  return scenarios;
}

function toFilterSet(value) {
  if (!value) {
    return undefined;
  }
  const values = Array.isArray(value) ? value : String(value).split(",");
  const normalized = values.map((item) => String(item).trim()).filter(Boolean);
  return normalized.length > 0 ? new Set(normalized) : undefined;
}

async function parseFixtureGroundTruth(filePath) {
  const lines = (await fs.readFile(filePath, "utf8")).split(/\r?\n/);
  const result = {
    fixtureId: undefined,
    kind: undefined,
    safeToRun: undefined,
    expectedFindings: [],
  };
  let inExpected = false;
  let current;

  const flush = () => {
    if (!current) return;
    result.expectedFindings.push(normalizeExpectedFinding(current));
    current = undefined;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    if (!line.startsWith(" ") && !line.startsWith("\t")) {
      if (trimmed.startsWith("fixtureId:")) {
        result.fixtureId = valueAfterColon(trimmed);
      } else if (trimmed.startsWith("kind:")) {
        result.kind = valueAfterColon(trimmed);
      } else if (trimmed.startsWith("safeToRun:")) {
        result.safeToRun = valueAfterColon(trimmed) === "true";
      }
      if (inExpected && !trimmed.startsWith("expectedFindings:")) {
        flush();
        inExpected = false;
      }
      if (trimmed === "expectedFindings: []") {
        result.expectedFindings = [];
        inExpected = false;
      } else if (trimmed === "expectedFindings:") {
        inExpected = true;
      }
      continue;
    }

    if (!inExpected) {
      continue;
    }
    if (trimmed.startsWith("- id:")) {
      flush();
      current = { id: valueAfterColon(trimmed.slice(2).trim()), cwe: [] };
      continue;
    }
    if (!current) {
      continue;
    }
    if (trimmed.startsWith("category:")) current.category = valueAfterColon(trimmed);
    else if (trimmed.startsWith("title:")) current.title = valueAfterColon(trimmed);
    else if (trimmed.startsWith("severity:")) current.severity = valueAfterColon(trimmed);
    else if (trimmed.startsWith("file:")) current.location = { ...(current.location ?? {}), file: valueAfterColon(trimmed) };
    else if (trimmed.startsWith("startLineHint:")) current.location = { ...(current.location ?? {}), startLine: Number(valueAfterColon(trimmed)) };
    else if (trimmed.startsWith("- CWE-")) current.cwe.push(trimmed.slice(2).trim());
  }
  flush();

  return {
    fixtureId: result.fixtureId,
    kind: result.kind ?? "unknown",
    safeToRun: result.safeToRun ?? false,
    expectedFindings: result.expectedFindings,
  };
}

function normalizeExpectedFinding(raw) {
  const finding = {
    id: raw.id,
    category: raw.category ?? "code",
    title: raw.title ?? raw.id,
    severity: raw.severity ?? "medium",
    cwe: raw.cwe ?? [],
  };
  if (raw.location?.file) {
    finding.location = {
      file: raw.location.file,
      ...(Number.isFinite(raw.location.startLine) ? { startLine: raw.location.startLine } : {}),
    };
  }
  return finding;
}

function valueAfterColon(line) {
  return line.slice(line.indexOf(":") + 1).trim().replace(/^["']|["']$/g, "");
}

async function prepareOutputDirectory(outDir) {
  await fs.mkdir(outDir, { recursive: true });
  await fs.rm(path.join(outDir, "runs"), { recursive: true, force: true });
  await fs.mkdir(path.join(outDir, "runs"), { recursive: true });
}

function buildCore(repoRoot) {
  const result = spawnSync("npm", ["run", "build:core"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "pipe",
    shell: process.platform === "win32",
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`npm run build:core failed:\n${tail(result.stdout)}\n${tail(result.stderr)}`);
  }
}

async function runActual({ repoRoot, outDir, scenario, fixture, timeoutMs }) {
  const runId = `${scenario.id}__${fixture.id}`;
  const runDir = path.join(outDir, "runs", runId);
  const reportOut = path.join(runDir, "reports");
  await fs.mkdir(runDir, { recursive: true });
  const args = [
    path.join(repoRoot, "dist/src/bin/hermsec.js"),
    "scan",
    fixture.absolutePath,
    "--mode",
    "auto",
    "--assist-mode",
    scenario.assistMode,
    "--out",
    reportOut,
    "--json",
  ];
  const env = {
    ...process.env,
    HERMSEC_MODEL_PROVIDER: MODEL_POLICY.provider,
    HERMSEC_MODEL: scenario.defaultModel,
    HERMSEC_MODEL_API_KEY_ENV: OPENCODE_GO_API_KEY_ENV,
    HERMSEC_ALLOW_REMOTE_PROVIDERS: "true",
    HERMSEC_SCANNER_ONLINE_UPDATES: "false",
    HERMSEC_BENCHMARK_EXPORT_RAW: "1",
    ...(scenario.routeConfig ? { HERMSEC_AGENT_MODEL_CONFIG: JSON.stringify(scenario.routeConfig) } : {}),
    ...(scenario.env ?? {}),
  };
  const started = Date.now();
  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    timeout: timeoutMs ?? 420_000,
    maxBuffer: 60 * 1024 * 1024,
  });
  const durationMs = Date.now() - started;
  const stdout = sanitizeString(result.stdout ?? "", repoRoot);
  const stderr = sanitizeString(result.stderr ?? "", repoRoot);
  let cliResult;
  let parseError;
  try {
    cliResult = JSON.parse(result.stdout);
  } catch (error) {
    parseError = error instanceof Error ? error.message : String(error);
  }

  await fs.writeFile(path.join(runDir, cliResult ? "stdout.json" : "stdout.txt"), cliResult
    ? `${JSON.stringify(sanitizeValue(cliResult, repoRoot), null, 2)}\n`
    : stdout, "utf8");
  await fs.writeFile(path.join(runDir, "stderr.log"), stderr, "utf8");

  const findings = Array.isArray(cliResult?.data?.scan?.findings) ? cliResult.data.scan.findings : [];
  const metrics = scoreFindings(fixture.expectedFindings, findings);
  const ok = result.status === 0 && cliResult?.ok === true;

  return {
    runId,
    source: "actual",
    scenarioId: scenario.id,
    scenarioLabel: scenario.label,
    assistMode: scenario.assistMode,
    modelTier: scenario.modelTier,
    provider: MODEL_POLICY.provider,
    models: scenario.routeModels,
    fixtureId: fixture.id,
    fixturePath: fixture.path,
    expectedFindingCount: fixture.expectedFindingCount,
    ok,
    exitCode: result.status,
    signal: result.signal,
    durationMs,
    stdoutBytes: Buffer.byteLength(result.stdout ?? "", "utf8"),
    stderrBytes: Buffer.byteLength(result.stderr ?? "", "utf8"),
    ...(parseError ? { parseError } : {}),
    ...(result.error ? { spawnError: result.error.message } : {}),
    metrics,
    findingCount: findings.length,
    reportArtifacts: reportArtifactsFromCli(cliResult, repoRoot),
    supportFiles: {
      stdout: toRepoRelativePath(repoRoot, path.join(runDir, cliResult ? "stdout.json" : "stdout.txt")),
      stderr: toRepoRelativePath(repoRoot, path.join(runDir, "stderr.log")),
    },
    stderrTail: tail(stderr, 1600),
  };
}

async function runDryRun({ repoRoot, outDir, scenario, fixture, generatedAt }) {
  const runId = `${scenario.id}__${fixture.id}`;
  const runDir = path.join(outDir, "runs", runId);
  await fs.mkdir(runDir, { recursive: true });
  const profile = DRY_RUN_PROFILES[scenario.id];
  const findings = syntheticFindings({ scenario, fixture, profile, generatedAt });
  const metrics = scoreFindings(fixture.expectedFindings, findings);
  const scan = {
    schemaVersion: "1.0",
    synthetic: true,
    generatedAt,
    runId,
    scenarioId: scenario.id,
    fixtureId: fixture.id,
    findings,
  };
  const supportPath = path.join(runDir, "dry-run-findings.json");
  await fs.writeFile(supportPath, `${JSON.stringify(scan, null, 2)}\n`, "utf8");
  return {
    runId,
    source: "dry-run",
    scenarioId: scenario.id,
    scenarioLabel: scenario.label,
    assistMode: scenario.assistMode,
    modelTier: scenario.modelTier,
    provider: MODEL_POLICY.provider,
    models: scenario.routeModels,
    fixtureId: fixture.id,
    fixturePath: fixture.path,
    expectedFindingCount: fixture.expectedFindingCount,
    ok: true,
    exitCode: 0,
    durationMs: profile.durationMs + fixture.expectedFindingCount * 1000,
    metrics,
    findingCount: findings.length,
    reportArtifacts: {},
    supportFiles: {
      findings: toRepoRelativePath(repoRoot, supportPath),
    },
  };
}

function syntheticFindings({ scenario, fixture, profile, generatedAt }) {
  const expected = fixture.expectedFindings;
  const hitCount = Math.min(expected.length, Math.round(expected.length * profile.hitRate));
  const falsePositiveCount = expected.length > 0 ? profile.falsePositivesVulnerable : profile.falsePositivesClean;
  const hits = expected.slice(0, hitCount).map((truth, index) => syntheticExpectedFinding({
    scenario,
    fixture,
    truth,
    index,
    generatedAt,
  }));
  const falsePositives = Array.from({ length: falsePositiveCount }, (_, index) => syntheticFalsePositive({
    scenario,
    fixture,
    index,
    generatedAt,
  }));
  return [...hits, ...falsePositives];
}

function syntheticExpectedFinding({ scenario, fixture, truth, index, generatedAt }) {
  return {
    id: `finding-${scenario.id}-${fixture.id}-${truth.id}`,
    title: truth.title,
    category: truth.category,
    severity: truth.severity,
    confidence: truth.severity === "low" ? "medium" : "high",
    description: `Deterministic dry-run match for ${truth.id}.`,
    evidence: `${truth.location?.file ?? fixture.path}:${truth.location?.startLine ?? 1} synthetic evidence for ${truth.id}.`,
    remediation: "Use the real benchmark path with OPENCODE_GO_API_KEY for publishable measurements.",
    tool: toolForScenario(scenario),
    cwe: truth.cwe,
    ...(truth.location ? { location: { ...truth.location } } : {}),
    agent: scenario.assistMode === "deep-assisted" ? undefined : {
      mode: scenario.assistMode,
      source: scenario.assistMode === "scanner-moa-assisted" ? "scanner-backed" : scenario.assistMode === "single-agent" ? "single-agent" : "moa-aggregator",
      provider: MODEL_POLICY.provider,
      model: scenario.defaultModel,
      role: scenario.assistMode === "single-agent" ? "single-agent-inspector" : "moa-aggregator",
      generatedAt,
      candidateIds: [`candidate-${scenario.id}-${fixture.id}-${index}`],
    },
    fingerprint: `fp-${scenario.id}-${fixture.id}-${truth.id}`,
  };
}

function syntheticFalsePositive({ scenario, fixture, index, generatedAt }) {
  const file = fixture.language.includes("python") ? "README.md" : "README.md";
  return {
    id: `finding-${scenario.id}-${fixture.id}-synthetic-fp-${index + 1}`,
    title: "Dry-run synthetic false positive",
    category: "config",
    severity: "medium",
    confidence: "medium",
    description: "Synthetic unmatched finding used to exercise precision scoring.",
    evidence: `${file}:1 synthetic unmatched evidence.`,
    remediation: "Ignore this deterministic dry-run artifact.",
    tool: toolForScenario(scenario),
    cwe: ["CWE-200"],
    location: { file, startLine: 1 },
    agent: scenario.assistMode === "deep-assisted" ? undefined : {
      mode: scenario.assistMode,
      source: scenario.assistMode === "single-agent" ? "single-agent" : "moa-aggregator",
      provider: MODEL_POLICY.provider,
      model: scenario.defaultModel,
      role: scenario.assistMode === "single-agent" ? "single-agent-inspector" : "moa-aggregator",
      generatedAt,
      candidateIds: [`candidate-${scenario.id}-${fixture.id}-fp-${index + 1}`],
    },
    fingerprint: `fp-${scenario.id}-${fixture.id}-synthetic-fp-${index + 1}`,
  };
}

function toolForScenario(scenario) {
  if (scenario.assistMode === "single-agent") return "hermsec-agent";
  if (scenario.assistMode === "moa-assisted") return "hermsec-moa";
  if (scenario.assistMode === "scanner-moa-assisted") return "hermsec-scanner-moa";
  return "hermsec-heuristics";
}

export function scoreFindings(expected, actual) {
  const { findings: dedupedActual, ignored } = dedupeActualFindings(actual);
  const candidates = [];
  for (const truth of expected) {
    for (const finding of dedupedActual) {
      const score = scoreMatch(truth, finding);
      if (score >= 60) {
        candidates.push({ expectedId: truth.id, findingId: finding.id, score });
      }
    }
  }

  const matches = [];
  const usedExpected = new Set();
  const usedActual = new Set();
  for (const candidate of candidates.sort((left, right) =>
    right.score - left.score ||
    left.expectedId.localeCompare(right.expectedId) ||
    left.findingId.localeCompare(right.findingId))) {
    if (!usedExpected.has(candidate.expectedId) && !usedActual.has(candidate.findingId)) {
      matches.push(candidate);
      usedExpected.add(candidate.expectedId);
      usedActual.add(candidate.findingId);
    }
  }

  const truePositive = matches.length;
  const falsePositive = dedupedActual.length - truePositive;
  const falseNegative = expected.length - truePositive;
  const precision = safeRatio(truePositive, truePositive + falsePositive, 1);
  const recall = safeRatio(truePositive, truePositive + falseNegative, 1);
  return {
    totalExpected: expected.length,
    totalActual: dedupedActual.length,
    truePositive,
    falsePositive,
    falseNegative,
    precision: round4(precision),
    recall: round4(recall),
    f1: round4(fScore(precision, recall)),
    matches,
    unmatchedExpected: expected.filter((item) => !usedExpected.has(item.id)).map((item) => item.id),
    unmatchedActual: dedupedActual.filter((item) => !usedActual.has(item.id)).map((item) => item.id),
    ignoredActual: ignored,
  };
}

function scoreMatch(expected, actual) {
  let score = 0;
  if (expected.category === actual.category) score += 20;
  if (expected.severity === actual.severity) score += 10;
  if (sameLocation(expected, actual)) score += 30;
  if (overlap(expected.cwe, actual.cwe)) score += 25;
  if (overlapIds(expected.identifiers, actual.identifiers)) score += 45;
  if (samePackage(expected, actual)) score += 30;
  return score;
}

function dedupeActualFindings(actual) {
  const byFingerprint = new Map();
  const ignored = [];
  for (const finding of actual) {
    const key = finding.fingerprint ?? finding.id;
    if (byFingerprint.has(key)) {
      ignored.push({
        findingId: finding.id,
        reason: "duplicate",
        duplicateOfId: byFingerprint.get(key).id,
      });
      continue;
    }
    byFingerprint.set(key, finding);
  }
  return { findings: [...byFingerprint.values()], ignored };
}

function sameLocation(expected, actual) {
  if (!expected.location?.file || !actual.location?.file) return false;
  if (normalizePath(expected.location.file) !== normalizePath(actual.location.file)) return false;
  if (!expected.location.startLine || !actual.location.startLine) return true;
  return Math.abs(expected.location.startLine - actual.location.startLine) <= 3;
}

function samePackage(expected, actual) {
  if (!expected.package || !actual.package) return false;
  return expected.package.ecosystem?.toLowerCase() === actual.package.ecosystem?.toLowerCase() &&
    expected.package.name?.toLowerCase() === actual.package.name?.toLowerCase();
}

function overlap(left, right) {
  if (!left?.length || !right?.length) return false;
  const normalized = new Set(right.map((item) => String(item).toUpperCase()));
  return left.some((item) => normalized.has(String(item).toUpperCase()));
}

function overlapIds(left, right) {
  return overlap(left?.cve, right?.cve) || overlap(left?.ghsa, right?.ghsa) || overlap(left?.osv, right?.osv);
}

function normalizePath(value) {
  return String(value).replace(/\\/g, "/").toLowerCase();
}

function aggregateRuns(runs, executionMode = "unknown", scenarios = SCENARIOS) {
  return scenarios.map((scenario) => {
    const scenarioRuns = runs.filter((run) => run.scenarioId === scenario.id);
    const counts = scenarioRuns.reduce((acc, run) => {
      acc.expected += run.metrics.totalExpected;
      acc.actual += run.metrics.totalActual;
      acc.truePositive += run.metrics.truePositive;
      acc.falsePositive += run.metrics.falsePositive;
      acc.falseNegative += run.metrics.falseNegative;
      acc.durationMs += run.durationMs ?? 0;
      if (run.ok) acc.okRuns += 1;
      return acc;
    }, { expected: 0, actual: 0, truePositive: 0, falsePositive: 0, falseNegative: 0, durationMs: 0, okRuns: 0 });
    const precision = safeRatio(counts.truePositive, counts.truePositive + counts.falsePositive, 1);
    const recall = safeRatio(counts.truePositive, counts.truePositive + counts.falseNegative, 1);
    return {
      scenarioId: scenario.id,
      scenarioLabel: scenario.label,
      executionMode,
      publishable: executionMode === "actual",
      assistMode: scenario.assistMode,
      modelTier: scenario.modelTier,
      provider: MODEL_POLICY.provider,
      models: scenario.routeModels,
      runs: scenarioRuns.length,
      okRuns: counts.okRuns,
      expected: counts.expected,
      actual: counts.actual,
      truePositive: counts.truePositive,
      falsePositive: counts.falsePositive,
      falseNegative: counts.falseNegative,
      precision: round4(precision),
      recall: round4(recall),
      f1: round4(fScore(precision, recall)),
      durationMs: counts.durationMs,
    };
  });
}

function renderMetricsCsv(summary) {
  const headers = [
    "scenario_id",
    "scenario_label",
    "execution_mode",
    "publishable",
    "assist_mode",
    "model_tier",
    "provider",
    "models",
    "runs",
    "ok_runs",
    "expected",
    "actual",
    "true_positive",
    "false_positive",
    "false_negative",
    "precision",
    "recall",
    "f1",
    "duration_ms",
  ];
  const rows = summary.map((row) => [
    row.scenarioId,
    row.scenarioLabel,
    row.executionMode,
    row.publishable ? "true" : "false",
    row.assistMode,
    row.modelTier,
    row.provider,
    row.models.join(";"),
    row.runs,
    row.okRuns,
    row.expected,
    row.actual,
    row.truePositive,
    row.falsePositive,
    row.falseNegative,
    row.precision,
    row.recall,
    row.f1,
    row.durationMs,
  ]);
  return `${[headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

function csvCell(value) {
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function buildChartData({ generatedAt, subset, executionMode, summary }) {
  return {
    schemaVersion: "1.0",
    generatedAt,
    subset,
    executionMode,
    labels: summary.map((row) => row.scenarioLabel),
    datasets: {
      precision: summary.map((row) => row.precision),
      recall: summary.map((row) => row.recall),
      f1: summary.map((row) => row.f1),
      falsePositive: summary.map((row) => row.falsePositive),
      falseNegative: summary.map((row) => row.falseNegative),
    },
    rows: summary.map((row) => ({
      scenarioId: row.scenarioId,
      label: row.scenarioLabel,
      precision: row.precision,
      recall: row.recall,
      f1: row.f1,
      truePositive: row.truePositive,
      falsePositive: row.falsePositive,
      falseNegative: row.falseNegative,
    })),
  };
}

function buildSubsetManifest({ subset, fixtures, scenarios, generatedAt, publicBenchmarks }) {
  return {
    schemaVersion: "1.0",
    generatedAt,
    subset,
    fixtureCount: fixtures.length,
    expectedFindingCount: fixtures.reduce((sum, fixture) => sum + fixture.expectedFindingCount, 0),
    fixtures: fixtures.map((fixture) => ({
      id: fixture.id,
      path: fixture.path,
      kind: fixture.kind,
      language: fixture.language,
      framework: fixture.framework,
      safeToRun: fixture.safeToRun,
      expectedFindingCount: fixture.expectedFindingCount,
      expectedFindings: fixture.expectedFindings.map((finding) => ({
        id: finding.id,
        category: finding.category,
        severity: finding.severity,
        cwe: finding.cwe,
        location: finding.location,
      })),
    })),
    scenarios: scenarios.map((scenario) => publicScenario(scenario)),
    modelPolicy: MODEL_POLICY,
    publicBenchmarks,
  };
}

function publicScenario(scenario) {
  return {
    id: scenario.id,
    label: scenario.label,
    assistMode: scenario.assistMode,
    modelTier: scenario.modelTier,
    provider: MODEL_POLICY.provider,
    defaultModel: scenario.defaultModel,
    routeModels: scenario.routeModels,
    scannerBacked: scenario.scannerBacked,
    routeConfig: scenario.routeConfig,
    env: scenario.env,
  };
}

function renderChartSvgs(summary) {
  return {
    metrics: renderGroupedBarChart({
      title: "HermSec mode quality metrics",
      subtitle: "Precision, recall, and F1 by scenario",
      series: [
        { id: "precision", label: "Precision", color: "#3b82f6", values: summary.map((row) => row.precision) },
        { id: "recall", label: "Recall", color: "#22c55e", values: summary.map((row) => row.recall) },
        { id: "f1", label: "F1", color: "#f59e0b", values: summary.map((row) => row.f1) },
      ],
      labels: summary.map((row) => row.scenarioLabel),
      maxValue: 1,
      valueFormatter: (value) => value.toFixed(2),
    }),
    counts: renderGroupedBarChart({
      title: "HermSec finding counts",
      subtitle: "True positives, false positives, and false negatives by scenario",
      series: [
        { id: "tp", label: "TP", color: "#22c55e", values: summary.map((row) => row.truePositive) },
        { id: "fp", label: "FP", color: "#ef4444", values: summary.map((row) => row.falsePositive) },
        { id: "fn", label: "FN", color: "#94a3b8", values: summary.map((row) => row.falseNegative) },
      ],
      labels: summary.map((row) => row.scenarioLabel),
      maxValue: Math.max(1, ...summary.flatMap((row) => [row.truePositive, row.falsePositive, row.falseNegative])),
      valueFormatter: (value) => String(value),
    }),
  };
}

function renderGroupedBarChart({ title, subtitle, labels, series, maxValue, valueFormatter }) {
  const width = 1120;
  const height = 640;
  const margin = { top: 86, right: 42, bottom: 150, left: 64 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const groupWidth = plotWidth / labels.length;
  const barGap = 6;
  const barWidth = Math.max(12, (groupWidth - 28 - barGap * (series.length - 1)) / series.length);
  const axisColor = "#334155";
  const textColor = "#0f172a";
  const mutedColor = "#64748b";
  const gridColor = "#e2e8f0";
  const max = maxValue <= 1 ? 1 : Math.ceil(maxValue);
  const ticks = max <= 1 ? [0, 0.25, 0.5, 0.75, 1] : Array.from({ length: Math.min(max, 8) + 1 }, (_, index) => Math.round((max / Math.min(max, 8)) * index));
  const bars = [];
  for (let labelIndex = 0; labelIndex < labels.length; labelIndex += 1) {
    const groupX = margin.left + labelIndex * groupWidth + 14;
    for (let seriesIndex = 0; seriesIndex < series.length; seriesIndex += 1) {
      const value = series[seriesIndex].values[labelIndex] ?? 0;
      const barHeight = max === 0 ? 0 : (value / max) * plotHeight;
      const x = groupX + seriesIndex * (barWidth + barGap);
      const y = margin.top + plotHeight - barHeight;
      bars.push(`<rect x="${round1(x)}" y="${round1(y)}" width="${round1(barWidth)}" height="${round1(barHeight)}" rx="4" fill="${series[seriesIndex].color}"/>`);
      bars.push(`<text x="${round1(x + barWidth / 2)}" y="${round1(y - 6)}" text-anchor="middle" font-size="11" fill="${mutedColor}">${escapeXml(valueFormatter(value))}</text>`);
    }
  }
  const tickLines = ticks.map((tick) => {
    const y = margin.top + plotHeight - (tick / max) * plotHeight;
    return [
      `<line x1="${margin.left}" y1="${round1(y)}" x2="${width - margin.right}" y2="${round1(y)}" stroke="${gridColor}" stroke-width="1"/>`,
      `<text x="${margin.left - 12}" y="${round1(y + 4)}" text-anchor="end" font-size="12" fill="${mutedColor}">${escapeXml(valueFormatter(tick))}</text>`,
    ].join("\n");
  }).join("\n");
  const labelTexts = labels.map((label, index) => {
    const x = margin.left + index * groupWidth + groupWidth / 2;
    return `<text x="${round1(x)}" y="${height - 88}" text-anchor="middle" font-size="12" fill="${textColor}">${escapeXml(label)}</text>`;
  }).join("\n");
  const legend = series.map((item, index) => {
    const x = margin.left + index * 160;
    return `<g transform="translate(${x},52)"><rect width="14" height="14" rx="3" fill="${item.color}"/><text x="22" y="12" font-size="13" fill="${textColor}">${escapeXml(item.label)}</text></g>`;
  }).join("\n");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeXml(title)}">
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="${margin.left}" y="30" font-size="24" font-weight="700" fill="${textColor}">${escapeXml(title)}</text>
  <text x="${margin.left}" y="54" font-size="14" fill="${mutedColor}">${escapeXml(subtitle)}</text>
  ${legend}
  ${tickLines}
  <line x1="${margin.left}" y1="${margin.top + plotHeight}" x2="${width - margin.right}" y2="${margin.top + plotHeight}" stroke="${axisColor}" stroke-width="1.5"/>
  <line x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${margin.top + plotHeight}" stroke="${axisColor}" stroke-width="1.5"/>
  ${bars.join("\n  ")}
  ${labelTexts}
</svg>
`;
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function round1(value) {
  return Number(value.toFixed(1));
}

function reportArtifactsFromCli(cliResult, repoRoot) {
  const report = cliResult?.data?.report;
  if (!report || typeof report !== "object") {
    return {};
  }
  return sanitizeValue(report, repoRoot);
}

function sanitizeValue(value, repoRoot) {
  if (typeof value === "string") return sanitizeString(value, repoRoot);
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, repoRoot));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, sanitizeValue(entry, repoRoot)]));
  }
  return value;
}

function sanitizeString(value, repoRoot) {
  let result = String(value);
  const secret = process.env[OPENCODE_GO_API_KEY_ENV];
  if (secret) {
    result = result.split(secret).join("[REDACTED]");
  }
  const normalizedRepo = repoRoot.replace(/\\/g, "/");
  result = result.split(repoRoot).join("<hermsec-repo>");
  result = result.split(normalizedRepo).join("<hermsec-repo>");
  return result;
}

function readGitMetadata(repoRoot) {
  const branch = git(["rev-parse", "--abbrev-ref", "HEAD"], repoRoot);
  const commit = git(["rev-parse", "HEAD"], repoRoot);
  const dirty = git(["status", "--short"], repoRoot);
  return {
    ...(branch ? { branch } : {}),
    ...(commit ? { commit } : {}),
    dirty: Boolean(dirty),
  };
}

function git(args, repoRoot) {
  const result = spawnSync("git", args, { cwd: repoRoot, encoding: "utf8", stdio: "pipe" });
  return result.status === 0 ? result.stdout.trim() : undefined;
}

function renderResultsReadme({ executionMode, subset, generatedAt }) {
  return `# Latest Task 5 Medium Benchmark Results

Generated by \`node scripts/research-task5-medium-benchmark.mjs\`.

- Generated at: ${generatedAt}
- Subset: ${subset}
- Execution mode: ${executionMode}
- Provider policy: OpenCode Go only, using efficient non-US models \`deepseek-v4-flash\`, \`mimo-v2.5\`, \`deepseek-v4-pro\` for judging, and \`minimax-m3\` for aggregation.

Files:

- \`metrics.csv\` - aggregate metrics by benchmark scenario.
- \`results.json\` - run-level records and aggregate summary.
- \`subset-manifest.json\` - selected fixtures, expected findings, scenarios, and model policy.
- \`chart-data.json\` - chart-ready precision/recall/F1 series.
- \`mode-metrics.svg\` - precision, recall, and F1 chart.
- \`mode-counts.svg\` - true/false positive and false-negative count chart.
- \`runs/\` - per-run support files.

When \`executionMode\` is \`dry-run\`, the findings are deterministic synthetic smoke data for validating the benchmark pipeline only. Use \`--actual\` with \`${OPENCODE_GO_API_KEY_ENV}\` set for publishable measurements.
`;
}

function safeRatio(numerator, denominator, emptyValue) {
  return denominator === 0 ? emptyValue : numerator / denominator;
}

function fScore(precision, recall) {
  return precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
}

function round4(value) {
  return Number(value.toFixed(4));
}

function toRepoRelativePath(repoRoot, targetPath) {
  return path.relative(repoRoot, targetPath).replace(/\\/g, "/");
}

function tail(value, maxChars = 4000) {
  const text = String(value ?? "");
  return text.length > maxChars ? text.slice(-maxChars) : text;
}

function parseArgs(values) {
  const parsed = {
    executionMode: "auto",
    subset: "medium",
    build: true,
  };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--help" || value === "-h") {
      parsed.help = true;
    } else if (value === "--dry-run") {
      parsed.executionMode = "dry-run";
    } else if (value === "--actual") {
      parsed.executionMode = "actual";
    } else if (value === "--smoke") {
      parsed.subset = "smoke";
      parsed.executionMode = "dry-run";
    } else if (value === "--no-build") {
      parsed.build = false;
    } else if (value === "--no-desktop-settings-key") {
      parsed.desktopSettings = false;
    } else if (value === "--out") {
      parsed.outDir = values[++index];
    } else if (value === "--subset") {
      parsed.subset = values[++index];
    } else if (value === "--scenario") {
      parsed.scenario = values[++index];
    } else if (value === "--fixture") {
      parsed.fixture = values[++index];
    } else if (value === "--timeout-ms") {
      parsed.timeoutMs = Number(values[++index]);
    } else if (value === "--generated-at") {
      parsed.generatedAt = values[++index];
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }
  return parsed;
}

function printHelp() {
  console.log(`Usage: node scripts/research-task5-medium-benchmark.mjs [--dry-run|--actual] [--subset medium|smoke|vulnerable-only] [--scenario <id[,id]>] [--fixture <id[,id]>] [--out <dir>] [--no-build] [--no-desktop-settings-key]

Runs the Task 5 medium benchmark matrix:
  Deep assisted, Single agent, MoA low/high, Scanner+MoA low/high.

Defaults to --actual only when ${OPENCODE_GO_API_KEY_ENV} is set or a saved OpenCode Go desktop key is available; otherwise it writes deterministic dry-run artifacts.`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  const result = await runBenchmark(args);
  console.log(`Task 5 benchmark artifacts written to ${toRepoRelativePath(DEFAULT_REPO_ROOT, result.outDir)}`);
  console.log(`Execution mode: ${result.executionMode}`);
  console.log(`Metrics: ${toRepoRelativePath(DEFAULT_REPO_ROOT, result.metricsPath)}`);
  console.log(`Results: ${toRepoRelativePath(DEFAULT_REPO_ROOT, result.resultsPath)}`);
  if (result.executionMode === "actual" && result.summary.some((row) => row.okRuns !== row.runs)) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
