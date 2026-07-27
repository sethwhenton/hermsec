import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, {
  after,
  before,
  type TestContext,
} from "node:test";
import { pathToFileURL } from "node:url";

const REPOSITORY_ROOT = path.resolve(".");
const PRODUCER = path.resolve(
  "scripts/research/run-seven-mode-experiment.mjs",
);
const SUMMARIZER = path.resolve(
  "scripts/research/summarize-seven-mode.mjs",
);
const EXPORTER = path.resolve(
  "scripts/research/generate-paper-results.mjs",
);
const PAPER_MAIN = path.resolve(
  "docs/research/task5-hermsec-moa/overleaf-paper-seven-mode-tool-agent/main.tex",
);

const MODES = [
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
] as const;

type Mode = (typeof MODES)[number];
type CellStatus =
  | "success"
  | "partial"
  | "degraded"
  | "canceled"
  | "failed";

type ModeSummary = {
  mode: Mode;
  metrics: {
    precision: number;
    recall: number;
    f1: number;
    classMacroF1: number;
    classWeightedF1: number;
  };
  classMetrics: Array<{
    f1: number;
    categorySupport: number;
  }>;
  completeness: {
    status: "complete" | "partial" | "degraded";
    plannedComponentCount: number;
    completedComponentCount: number;
    failedComponentCount: number;
    skippedComponentCount: number;
    componentCompletionRate: number;
    fileCoverage: number | null;
    unsupportedLanguageCount: number;
    degradedReasonCount: number;
  };
  statusCounts: Record<CellStatus, number>;
  degradation: {
    affectedCaseCount: number;
    reasonCount: number;
  };
  evidenceCaveat: string;
  cost: {
    attributedCostUsd: number;
  };
};

type SummaryDocument = {
  schemaVersion: "1.0";
  suiteId: string;
  execution: "mock" | "replay" | "live";
  fixtureCount: number;
  modeCount: number;
  cellCount: number;
  modeOrder: Mode[];
  totals: {
    actualPhysicalSpendUsd: number;
    statusCounts: Record<CellStatus, number>;
  };
  modes: ModeSummary[];
  [key: string]: unknown;
};

type IntegrityReceipt = {
  schemaVersion: "1.0";
  suiteId: string;
  upstreamBindingSha256: string;
  outputBindings: DigestBinding[];
  outputSetSha256: string;
  receiptSha256: string;
  [key: string]: unknown;
};

type MutableIntegrityReceipt = IntegrityReceipt & {
  generator: DigestBinding;
  upstream: {
    suiteIndex: { sha256: string; [key: string]: unknown };
    sourceTruth: Array<Record<string, unknown>>;
    sourceTruthSetSha256: string;
    [key: string]: unknown;
  };
  derivationBindingSha256: string;
};

type DigestBinding = {
  path: string;
  bytes: number;
  sha256: string;
};

type StructuralFileRecord = {
  path: string;
  bytes: number;
  sha256: string;
};

type StructuralSourceState = {
  schemaVersion: string;
  fixtureId: string;
  pairId: string;
  variant: "vulnerable" | "clean";
  language: string;
  files: StructuralFileRecord[];
  fixtureDigestSha256: string;
  project: {
    root: string;
    files: StructuralFileRecord[];
    projectDigestSha256: string;
  };
  evaluator: {
    files: StructuralFileRecord[];
    evaluatorDigestSha256: string;
  };
  layoutBindingSha256: string;
  subject: {
    files: StructuralFileRecord[];
    subjectDigestSha256: string;
    excludedControlFiles: string[];
    fixtureBindingSha256: string;
  };
};

const MODE_STEMS: Record<Mode, string> = {
  "scanner-only": "ScannerOnly",
  "single-agent": "SingleAgent",
  "moa-low": "MoaLow",
  "moa-high": "MoaHigh",
  "scanner-single": "ScannerSingle",
  "scanner-moa-low": "ScannerMoaLow",
  "scanner-moa-high": "ScannerMoaHigh",
};

const SUMMARY_OUTPUT_FILES = [
  "completeness.csv",
  "cost-table.tex",
  "cost.csv",
  "metrics-table.tex",
  "metrics.csv",
  "metrics.md",
  "summary.json",
] as const;

const SUMMARY_FILES = [
  ...SUMMARY_OUTPUT_FILES,
  "integrity-receipt.json",
].sort();

let canonicalRoot = "";
let canonicalSuite = "";
let canonicalSummary = "";

before(async () => {
  canonicalRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-paper-contract-"),
  );
  canonicalSuite = path.join(canonicalRoot, "suite");
  canonicalSummary = path.join(canonicalRoot, "summary");

  const produced = await runNode(PRODUCER, [
    "--execution",
    "mock",
    "--dataset",
    "micro",
    "--suite-id",
    "paper-export-contract-suite",
    "--out",
    canonicalSuite,
  ]);
  assert.equal(
    produced.code,
    0,
    `producer contract fixture failed: ${produced.stderr}`,
  );

  const summarized = await runNode(SUMMARIZER, [
    "--suite",
    canonicalSuite,
    "--out",
    canonicalSummary,
  ]);
  assert.equal(
    summarized.code,
    0,
    `summarizer contract fixture failed: ${summarized.stderr}`,
  );
  assert.deepEqual(
    (await fs.readdir(canonicalSummary)).sort(),
    SUMMARY_FILES,
  );
});

after(async () => {
  if (canonicalRoot) {
    await fs.rm(canonicalRoot, { recursive: true, force: true });
  }
});

test("exports a fresh producer v3 suite and receipt-bound summary deterministically", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-stable-");
  const outputA = path.join(root, "paper-a");
  const outputB = path.join(root, "paper-b");

  const first = await runExporter(
    canonicalSummary,
    canonicalSuite,
    outputA,
  );
  const second = await runExporter(
    canonicalSummary,
    canonicalSuite,
    outputB,
  );
  assert.equal(first.code, 0, first.stderr);
  assert.equal(second.code, 0, second.stderr);
  assert.deepEqual(await listTree(outputA), [
    "generated/",
    "generated/results-macros.tex",
    "generated/results-provenance.json",
  ]);
  assert.deepEqual(await listTree(outputB), await listTree(outputA));

  for (const relativePath of [
    "generated/results-macros.tex",
    "generated/results-provenance.json",
  ]) {
    assert.equal(
      await fs.readFile(path.join(outputA, relativePath), "utf8"),
      await fs.readFile(path.join(outputB, relativePath), "utf8"),
      `${relativePath} changed across identical input`,
    );
  }

  const summary = await readSummary(canonicalSummary);
  const receipt = JSON.parse(
    await fs.readFile(
      path.join(canonicalSummary, "integrity-receipt.json"),
      "utf8",
    ),
  ) as IntegrityReceipt & {
    upstream: {
      sourceTruth: Array<{
        projectDigestSha256: string;
        evaluatorDigestSha256: string;
        layoutBindingSha256: string;
        subjectDigestSha256: string;
        subjectFixtureBindingSha256: string;
      }>;
    };
  };
  assert.ok(receipt.upstream.sourceTruth.length > 0);
  for (const binding of receipt.upstream.sourceTruth) {
    assert.match(binding.projectDigestSha256, /^[a-f0-9]{64}$/u);
    assert.match(binding.evaluatorDigestSha256, /^[a-f0-9]{64}$/u);
    assert.match(binding.layoutBindingSha256, /^[a-f0-9]{64}$/u);
    assert.equal(
      binding.subjectDigestSha256,
      binding.projectDigestSha256,
    );
    assert.equal(
      binding.subjectFixtureBindingSha256,
      binding.layoutBindingSha256,
    );
  }
  const macros = await fs.readFile(
    path.join(outputA, "generated/results-macros.tex"),
    "utf8",
  );
  assert.match(
    macros,
    /\\newcommand\{\\DatasetFixtureCount\}\{\d+\}/u,
  );
  assert.match(
    macros,
    /\\newcommand\{\\ExpectedCellCount\}\{\d+\}/u,
  );
  assert.match(
    macros,
    /\\newcommand\{\\ManifestValidationRate\}\{1\.000\}/u,
  );
  assert.match(
    macros,
    /\\newcommand\{\\ReplayAgreement\}\{\\ResultUnavailable\}/u,
  );
  assert.match(
    macros,
    /\\newcommand\{\\MedianWallClockTime\}\{[0-9.]+\\,ms\}/u,
  );
  for (const mode of summary.modes) {
    const stem = MODE_STEMS[mode.mode];
    const expected = isEligible(mode, summary.fixtureCount)
      ? mode.metrics.f1.toFixed(3)
      : "\\ResultUnavailable";
    assert.equal(macroValue(macros, `${stem}FOne`), expected);
  }

  const provenanceText = await fs.readFile(
    path.join(outputA, "generated/results-provenance.json"),
    "utf8",
  );
  assert.equal(provenanceText.includes(canonicalRoot), false);
  const provenance = JSON.parse(provenanceText) as {
    schemaVersion: string;
    inputContract: {
      schemaVersion: string;
      requiredReceiptSchemaVersion: string;
      requiredSuiteIndexSchemaVersion: number;
    };
    source: {
      artifacts: DigestBinding[];
      integrityReceiptSha256: string;
      upstreamBindingSha256: string;
      suiteIndexSha256: string;
      suiteIndexFileSha256: string;
    };
    validation: {
      receiptVerification: string;
      v3SuiteTrustChain: string;
      deterministicSummarizerRerun: string;
    };
    optionalEvidence: {
      replayAgreement: { available: boolean };
      runtime: { available: boolean; sampleCount: number };
    };
  };
  assert.equal(provenance.schemaVersion, "2.0");
  assert.deepEqual(provenance.inputContract, {
    schemaVersion: "2.0",
    requiredSummarySchemaVersion: "1.0",
    requiredReceiptSchemaVersion: "1.0",
    requiredSuiteIndexSchemaVersion: 3,
  });
  assert.deepEqual(
    provenance.source.artifacts.map((entry) => entry.path),
    SUMMARY_FILES,
  );
  assert.match(provenance.source.integrityReceiptSha256, /^[a-f0-9]{64}$/u);
  assert.match(provenance.source.upstreamBindingSha256, /^[a-f0-9]{64}$/u);
  assert.match(provenance.source.suiteIndexSha256, /^[a-f0-9]{64}$/u);
  assert.match(provenance.source.suiteIndexFileSha256, /^[a-f0-9]{64}$/u);
  assert.equal(provenance.validation.receiptVerification, "passed");
  assert.equal(provenance.validation.v3SuiteTrustChain, "passed");
  assert.equal(
    provenance.validation.deterministicSummarizerRerun,
    "byte-identical",
  );
  assert.equal(provenance.optionalEvidence.replayAgreement.available, false);
  assert.equal(provenance.optionalEvidence.runtime.available, true);
  assert.equal(
    provenance.optionalEvidence.runtime.sampleCount,
    summary.cellCount,
  );
  assert.deepEqual(
    (await fs.readdir(root))
      .filter((entry) => entry.includes(".tmp-"))
      .sort(),
    [],
  );
});

test("requires structural source-state v2 and enforces the project/evaluator boundary", async () => {
  const module = (await import(pathToFileURL(EXPORTER).href)) as {
    validateStructuralSourceState: (
      value: unknown,
      fixtureId: string,
    ) => StructuralSourceState;
  };
  const validate = module.validateStructuralSourceState;
  const fixtureId = "paper-structural-contract";
  const valid = createStructuralSourceState(fixtureId);

  const normalized = validate(valid, fixtureId);
  assert.equal(normalized.schemaVersion, "2.0");
  assert.ok(
    normalized.project.files.some(
      (file) => file.path === "project-data/truth.json",
    ),
    "a truth.json filename inside the explicit project/ subtree is project data",
  );
  assert.equal(
    normalized.subject.subjectDigestSha256,
    normalized.project.projectDigestSha256,
  );
  assert.equal(
    normalized.subject.fixtureBindingSha256,
    normalized.layoutBindingSha256,
  );

  const legacy = structuredClone(valid);
  legacy.schemaVersion = "1.0";
  assert.throws(
    () => validate(legacy, fixtureId),
    /legacy structural source-state schema 1\.0/iu,
  );

  const partial = structuredClone(valid);
  const partialProject = partial.project as unknown as Record<
    string,
    unknown
  >;
  delete partialProject.projectDigestSha256;
  assert.throws(
    () => validate(partial, fixtureId),
    /invalid field set.*projectDigestSha256/iu,
  );

  const unclassified = createStructuralSourceState(fixtureId, [
    ...valid.files,
    structuralFile("review/notes.json", "unclassified evaluator data"),
  ]);
  assert.throws(
    () => validate(unclassified, fixtureId),
    /unclassified or misplaced path/iu,
  );

  const swapped = structuredClone(valid);
  const projectFiles = swapped.project.files;
  swapped.project.files = swapped.evaluator.files;
  swapped.evaluator.files = projectFiles;
  rebindStructuralState(swapped);
  assert.throws(
    () => validate(swapped, fixtureId),
    /project-relative inventory|evaluator inventory/iu,
  );
});

test("the paper consumes every generated macro in its intended context", async () => {
  const summary = await readSummary(canonicalSummary);
  const module = (await import(pathToFileURL(EXPORTER).href)) as {
    renderResultMacros: (summary: SummaryDocument) => string;
  };
  const macros = module.renderResultMacros(summary);
  const paper = await fs.readFile(PAPER_MAIN, "utf8");

  assertPaperMacroConsumption(macros, paper);
});

test("requires the original v3 suite and rejects an unrelated suite path", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-suite-");
  const noSuite = await runNode(EXPORTER, [
    "--summary",
    canonicalSummary,
    "--out",
    path.join(root, "no-suite"),
  ]);
  assert.equal(noSuite.code, 1);
  assert.match(noSuite.stderr, /--suite is required/u);

  const unrelatedSuite = path.join(root, "not-a-suite");
  await fs.mkdir(unrelatedSuite);
  const unrelated = await runExporter(
    canonicalSummary,
    unrelatedSuite,
    path.join(root, "unrelated-output"),
  );
  assert.equal(unrelated.code, 1);
  assert.match(
    unrelated.stderr,
    /v3 (?:suite|index)|suite validator|suite integrity/iu,
  );
  await assert.rejects(fs.access(path.join(root, "unrelated-output")));
});

test("rejects individual artifact tampering and a coherent eight-file rewrite", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-tamper-");
  const singleSource = path.join(root, "single");
  await copyDirectory(canonicalSummary, singleSource);
  await fs.appendFile(path.join(singleSource, "metrics.csv"), "tampered\n");
  const single = await runExporter(
    singleSource,
    canonicalSuite,
    path.join(root, "single-output"),
  );
  assert.equal(single.code, 1);
  assert.match(single.stderr, /does not reconcile|digest|secret/iu);

  const coherentSource = path.join(root, "coherent");
  await copyDirectory(canonicalSummary, coherentSource);
  const coherentSummary = await readSummary(coherentSource);
  coherentSummary.modes[0]!.evidenceCaveat =
    "coherently rewritten but not derived from the suite";
  await rewriteSummaryAndReceipt(coherentSource, coherentSummary);
  const coherent = await runExporter(
    coherentSource,
    canonicalSuite,
    path.join(root, "coherent-output"),
  );
  assert.equal(coherent.code, 1);
  assert.match(
    coherent.stderr,
    /does not match deterministic derivation/u,
  );
  await assert.rejects(fs.access(path.join(root, "coherent-output")));
});

test("rejects receipt tampering and partial eight-artifact input", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-receipt-");
  const receiptSource = path.join(root, "receipt");
  await copyDirectory(canonicalSummary, receiptSource);
  const receiptPath = path.join(
    receiptSource,
    "integrity-receipt.json",
  );
  const receipt = JSON.parse(
    await fs.readFile(receiptPath, "utf8"),
  ) as IntegrityReceipt;
  receipt.upstreamBindingSha256 = "0".repeat(64);
  await fs.writeFile(
    receiptPath,
    `${JSON.stringify(receipt, null, 2)}\n`,
    "utf8",
  );
  const tampered = await runExporter(
    receiptSource,
    canonicalSuite,
    path.join(root, "receipt-output"),
  );
  assert.equal(tampered.code, 1);
  assert.match(tampered.stderr, /receipt|digest|binding/iu);

  const partialBindingSource = path.join(root, "partial-binding");
  await copyDirectory(canonicalSummary, partialBindingSource);
  const partialBindingPath = path.join(
    partialBindingSource,
    "integrity-receipt.json",
  );
  const partialBindingReceipt = JSON.parse(
    await fs.readFile(partialBindingPath, "utf8"),
  ) as MutableIntegrityReceipt;
  assert.ok(partialBindingReceipt.upstream.sourceTruth[0]);
  delete partialBindingReceipt.upstream.sourceTruth[0]
    .projectDigestSha256;
  rebindIntegrityReceipt(partialBindingReceipt);
  await fs.writeFile(
    partialBindingPath,
    `${JSON.stringify(partialBindingReceipt, null, 2)}\n`,
    "utf8",
  );
  const partialBinding = await runExporter(
    partialBindingSource,
    canonicalSuite,
    path.join(root, "partial-binding-output"),
  );
  assert.equal(partialBinding.code, 1);
  assert.match(
    partialBinding.stderr,
    /invalid field set.*projectDigestSha256/iu,
  );

  const partialSource = path.join(root, "partial");
  await copyDirectory(canonicalSummary, partialSource);
  await fs.rm(path.join(partialSource, "integrity-receipt.json"));
  const partial = await runExporter(
    partialSource,
    canonicalSuite,
    path.join(root, "partial-output"),
  );
  assert.equal(partial.code, 1);
  assert.match(partial.stderr, /artifact inventory/u);
});

test("recomputes class macro and weighted F1 and rejects a mismatch", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-class-f1-");
  for (const [field, errorPattern] of [
    ["classMacroF1", /recomputed class macro F1/u],
    ["classWeightedF1", /recomputed class weighted F1/u],
  ] as const) {
    const source = path.join(root, field);
    await copyDirectory(canonicalSummary, source);
    const summary = await readSummary(source);
    const target = summary.modes.find(
      (mode) => mode.classMetrics.length > 0,
    );
    assert.ok(target, "contract fixture should contain class metrics");
    target.metrics[field] =
      target.metrics[field] === 0 ? 0.5 : target.metrics[field] / 2;
    await rewriteSummaryAndReceipt(source, summary);
    const output = path.join(root, `${field}-output`);
    const result = await runExporter(source, canonicalSuite, output);
    assert.equal(result.code, 1);
    assert.match(result.stderr, errorPattern);
    await assert.rejects(fs.access(output));
  }
});

test("renders incomplete modes as N/A and excludes them from best-mode selection", async () => {
  const summary = structuredClone(await readSummary(canonicalSummary));
  for (const mode of summary.modes) {
    mode.completeness.status = "partial";
  }
  const module = (await import(pathToFileURL(EXPORTER).href)) as {
    renderResultMacros: (summary: SummaryDocument) => string;
  };
  const macros = module.renderResultMacros(summary);
  for (const mode of summary.modes) {
    const stem = MODE_STEMS[mode.mode];
    assert.equal(
      macroValue(macros, `${stem}Precision`),
      "\\ResultUnavailable",
    );
    assert.equal(
      macroValue(macros, `${stem}Recall`),
      "\\ResultUnavailable",
    );
    assert.equal(
      macroValue(macros, `${stem}FOne`),
      "\\ResultUnavailable",
    );
    assert.equal(
      macroValue(macros, `${stem}Cost`),
      "\\ResultUnavailable",
    );
  }
  assert.equal(
    macroValue(macros, "BestFOneMode"),
    "\\ResultUnavailable",
  );
  assert.equal(
    macroValue(macros, "BestPrecisionValue"),
    "\\ResultUnavailable",
  );
  assert.equal(
    macroValue(macros, "BestRecallValue"),
    "\\ResultUnavailable",
  );
});

test("rejects unbound summary evidence instead of publishing it", async () => {
  const summary = structuredClone(await readSummary(canonicalSummary));
  summary.paperEvidence = {
    replayAgreement: {
      matchingCells: summary.cellCount,
      totalCells: summary.cellCount,
      sourceSuiteId: "unbound-source",
      replaySuiteId: summary.suiteId,
    },
    runtime: {
      medianWallClockMs: 1,
      sampleCount: summary.cellCount,
    },
  };
  const module = (await import(pathToFileURL(EXPORTER).href)) as {
    validateSummary: (summary: SummaryDocument) => unknown;
  };
  assert.throws(
    () => module.validateSummary(summary),
    /invalid field set.*paperEvidence/iu,
  );
});

test("rejects Google, Slack, JWT, database URI, and project credential families", async (t) => {
  const credentials = [
    `AIza${"A".repeat(35)}`,
    `xoxb-${"B".repeat(24)}`,
    `eyJ${"a".repeat(12)}.eyJ${"b".repeat(12)}.${"c".repeat(16)}`,
    "postgresql://paper_user:not-a-real-password@db.invalid/hermsec",
    `sk-or-v1-${"d".repeat(32)}`,
    `sk-ant-${"e".repeat(28)}`,
    `npm_${"f".repeat(24)}`,
    `hf_${"g".repeat(24)}`,
  ];
  for (const [index, credential] of credentials.entries()) {
    await t.test(`credential family ${index + 1}`, async () => {
      const root = await fs.mkdtemp(
        path.join(os.tmpdir(), `hermsec-paper-secret-${index}-`),
      );
      try {
        const source = path.join(root, "summary");
        await copyDirectory(canonicalSummary, source);
        await fs.appendFile(
          path.join(source, "metrics.md"),
          `\ncredential-under-test: ${credential}\n`,
        );
        const result = await runExporter(
          source,
          canonicalSuite,
          path.join(root, "output"),
        );
        assert.equal(result.code, 1);
        assert.match(result.stderr, /Potential secret material/u);
        assert.equal(result.stderr.includes(credential), false);
      } finally {
        await fs.rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("rejects traversal claims, junction inputs, and output aliases into inputs", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-paths-");
  const traversalSource = path.join(root, "traversal");
  await copyDirectory(canonicalSummary, traversalSource);
  const traversalSummary = await readSummary(traversalSource);
  traversalSummary.suiteId = "../private-suite";
  await rewriteSummaryAndReceipt(traversalSource, traversalSummary);
  const traversal = await runExporter(
    traversalSource,
    canonicalSuite,
    path.join(root, "traversal-output"),
  );
  assert.equal(traversal.code, 1);
  assert.match(traversal.stderr, /unsafe path|suiteId/iu);

  const summaryLink = path.join(root, "summary-link");
  await createDirectoryLink(canonicalSummary, summaryLink);
  const linkedSummary = await runExporter(
    summaryLink,
    canonicalSuite,
    path.join(root, "linked-summary-output"),
  );
  assert.equal(linkedSummary.code, 1);
  assert.match(linkedSummary.stderr, /symbolic link|junction/u);

  const suiteLink = path.join(root, "suite-link");
  await createDirectoryLink(canonicalSuite, suiteLink);
  const linkedSuite = await runExporter(
    canonicalSummary,
    suiteLink,
    path.join(root, "linked-suite-output"),
  );
  assert.equal(linkedSuite.code, 1);
  assert.match(linkedSuite.stderr, /symbolic link|junction/u);

  const outputAlias = path.join(root, "summary-alias");
  await createDirectoryLink(canonicalSummary, outputAlias);
  const aliasedOutput = path.join(outputAlias, "paper-output");
  const aliasResult = await runExporter(
    canonicalSummary,
    canonicalSuite,
    aliasedOutput,
  );
  assert.equal(aliasResult.code, 1);
  assert.match(aliasResult.stderr, /must not resolve inside/u);
  await assert.rejects(fs.access(aliasedOutput));
});

test("preserves seeded output paths and never publishes a partial directory", async (t) => {
  const root = await temporaryRoot(t, "hermsec-paper-export-seeded-");
  const seededDirectory = path.join(root, "seeded-directory");
  await fs.mkdir(seededDirectory);
  const sentinel = path.join(seededDirectory, "sentinel.txt");
  await fs.writeFile(sentinel, "preserve\n", "utf8");
  const directoryResult = await runExporter(
    canonicalSummary,
    canonicalSuite,
    seededDirectory,
  );
  assert.equal(directoryResult.code, 1);
  assert.match(directoryResult.stderr, /already exists/u);
  assert.equal(await fs.readFile(sentinel, "utf8"), "preserve\n");

  const seededFile = path.join(root, "seeded-file");
  await fs.writeFile(seededFile, "preserve-file\n", "utf8");
  const fileResult = await runExporter(
    canonicalSummary,
    canonicalSuite,
    seededFile,
  );
  assert.equal(fileResult.code, 1);
  assert.match(fileResult.stderr, /already exists/u);
  assert.equal(
    await fs.readFile(seededFile, "utf8"),
    "preserve-file\n",
  );
  assert.deepEqual(
    (await fs.readdir(root))
      .filter((entry) => entry.includes(".tmp-"))
      .sort(),
    [],
  );
});

function createStructuralSourceState(
  fixtureId: string,
  files: StructuralFileRecord[] = [
    structuralFile("fixture.json", '{"fixture":true}\n'),
    structuralFile("project/package.json", '{"private":true}\n'),
    structuralFile(
      "project/project-data/truth.json",
      '{"applicationData":true}\n',
    ),
    structuralFile("project/src/index.js", "export const ready = true;\n"),
    structuralFile("truth.json", '{"findings":[]}\n'),
  ],
): StructuralSourceState {
  const fullFiles = [...files].sort((left, right) =>
    left.path.localeCompare(right.path),
  );
  const projectFiles = fullFiles
    .filter((file) => file.path.startsWith("project/"))
    .map((file) => ({
      ...file,
      path: file.path.slice("project/".length),
    }));
  const evaluatorFiles = fullFiles.filter(
    (file) => !file.path.startsWith("project/"),
  );
  return rebindStructuralState({
    schemaVersion: "2.0",
    fixtureId,
    pairId: "paper-structural-pair",
    variant: "clean",
    language: "javascript",
    files: fullFiles,
    fixtureDigestSha256: "",
    project: {
      root: "project",
      files: projectFiles,
      projectDigestSha256: "",
    },
    evaluator: {
      files: evaluatorFiles,
      evaluatorDigestSha256: "",
    },
    layoutBindingSha256: "",
    subject: {
      files: projectFiles,
      subjectDigestSha256: "",
      excludedControlFiles: evaluatorFiles.map((file) => file.path),
      fixtureBindingSha256: "",
    },
  });
}

function rebindStructuralState(
  state: StructuralSourceState,
): StructuralSourceState {
  state.fixtureDigestSha256 = sha256(prettyCanonicalJson(state.files));
  state.project.projectDigestSha256 = sha256(
    prettyCanonicalJson(state.project.files),
  );
  state.evaluator.evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(state.evaluator.files),
  );
  state.layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: "project",
      fixtureDigestSha256: state.fixtureDigestSha256,
      projectDigestSha256: state.project.projectDigestSha256,
      evaluatorDigestSha256:
        state.evaluator.evaluatorDigestSha256,
    }),
  );
  state.subject = {
    files: state.project.files.map((file) => ({ ...file })),
    subjectDigestSha256: state.project.projectDigestSha256,
    excludedControlFiles: state.evaluator.files.map((file) => file.path),
    fixtureBindingSha256: state.layoutBindingSha256,
  };
  return state;
}

function structuralFile(
  filePath: string,
  content: string,
): StructuralFileRecord {
  return {
    path: filePath,
    bytes: Buffer.byteLength(content, "utf8"),
    sha256: sha256(content),
  };
}

function isEligible(mode: ModeSummary, fixtureCount: number) {
  return (
    mode.statusCounts.success === fixtureCount &&
    mode.statusCounts.partial === 0 &&
    mode.statusCounts.degraded === 0 &&
    mode.statusCounts.canceled === 0 &&
    mode.statusCounts.failed === 0 &&
    mode.completeness.status === "complete" &&
    mode.completeness.completedComponentCount ===
      mode.completeness.plannedComponentCount &&
    mode.completeness.failedComponentCount === 0 &&
    mode.completeness.skippedComponentCount === 0 &&
    mode.completeness.componentCompletionRate === 1 &&
    (mode.completeness.fileCoverage === null ||
      mode.completeness.fileCoverage === 1) &&
    mode.completeness.unsupportedLanguageCount === 0 &&
    mode.completeness.degradedReasonCount === 0 &&
    mode.degradation.affectedCaseCount === 0 &&
    mode.degradation.reasonCount === 0
  );
}

function macroValue(macros: string, name: string) {
  const marker = `\\newcommand{\\${name}}{`;
  const start = macros.indexOf(marker);
  assert.notEqual(start, -1, `missing macro ${name}`);
  const valueStart = start + marker.length;
  const end = macros.indexOf("}\n", valueStart);
  assert.notEqual(end, -1, `unterminated macro ${name}`);
  return macros.slice(valueStart, end);
}

function assertPaperMacroConsumption(macros: string, paper: string) {
  const generatedNames = [
    ...macros.matchAll(
      /\\newcommand\{\\([A-Za-z][A-Za-z0-9]*)\}/gu,
    ),
  ].map((match) => match[1]!);
  assert.equal(
    new Set(generatedNames).size,
    generatedNames.length,
    "generated macro names must be unique",
  );

  const expectedContexts: Record<string, string> = {
    ResultPending: "\\textbf{RQ1.} \\ResultPending.",
    DatasetFixtureCount:
      "Across \\DatasetFixtureCount{} fixtures and \\DatasetTruthCount{} truth labels",
    DatasetTruthCount:
      "Across \\DatasetFixtureCount{} fixtures and \\DatasetTruthCount{} truth labels",
    CompletedCellCount:
      "Successful cells & \\CompletedCellCount \\\\",
    ExpectedCellCount: "Planned cells & \\ExpectedCellCount \\\\",
    PartialCellCount: "Partial cells & \\PartialCellCount \\\\",
    DegradedCellCount: "Degraded cells & \\DegradedCellCount \\\\",
    CanceledCellCount: "Canceled cells & \\CanceledCellCount \\\\",
    FailedCellCount: "Failed cells & \\FailedCellCount \\\\",
    BestFOneMode:
      "The strongest F1 mode was \\BestFOneMode{} with \\BestFOneValue{}.",
    BestFOneValue:
      "The strongest F1 mode was \\BestFOneMode{} with \\BestFOneValue{}.",
    BestPrecisionMode:
      "The strongest precision mode was \\BestPrecisionMode{} with \\BestPrecisionValue{}",
    BestPrecisionValue:
      "The strongest precision mode was \\BestPrecisionMode{} with \\BestPrecisionValue{}",
    BestRecallMode:
      "the strongest recall mode was \\BestRecallMode{} with \\BestRecallValue{}.",
    BestRecallValue:
      "the strongest recall mode was \\BestRecallMode{} with \\BestRecallValue{}.",
    TotalPhysicalCost: "total provider cost of \\TotalPhysicalCost{}",
    ReplayAgreement: "Replay agreement & \\ReplayAgreement \\\\",
    ManifestValidationRate:
      "Manifest validation rate & \\ManifestValidationRate \\\\",
    MedianWallClockTime:
      "median wall-clock time was \\MedianWallClockTime{}.",
  };

  for (const mode of MODES) {
    const stem = MODE_STEMS[mode];
    const row =
      `\\mode{${mode}} & \\${stem}Precision & \\${stem}Recall & ` +
      `\\${stem}FOne & \\${stem}Cost \\\\`;
    for (const suffix of ["Precision", "Recall", "FOne", "Cost"]) {
      expectedContexts[`${stem}${suffix}`] = row;
    }
  }

  const deliberatelyNotRendered: Record<string, string> = {
    ResultUnavailable:
      "Helper macro consumed indirectly by generated N/A metric values.",
    ExperimentSuiteId:
      "Suite identity is retained in generated provenance rather than repeated in the manuscript.",
    DatasetSuiteCount:
      "The exporter accepts one bound suite, so this provenance value is not a manuscript row.",
    ExperimentExecution:
      "Execution type is retained in generated provenance rather than repeated in the manuscript.",
  };

  const contractedNames = [
    ...Object.keys(expectedContexts),
    ...Object.keys(deliberatelyNotRendered),
  ].sort();
  assert.deepEqual(
    [...generatedNames].sort(),
    contractedNames,
    "every generated macro must have a paper context or an explicit non-rendering rationale",
  );

  for (const [name, context] of Object.entries(expectedContexts)) {
    assert.match(
      paper,
      new RegExp(`\\\\${name}(?![A-Za-z])`, "u"),
      `${name} is not consumed by main.tex`,
    );
    assert.ok(
      paper.includes(context),
      `${name} is not consumed in its intended paper context`,
    );
  }

  for (const [name, rationale] of Object.entries(
    deliberatelyNotRendered,
  )) {
    assert.ok(
      rationale.length >= 20,
      `${name} needs a deliberate non-rendering rationale`,
    );
    assert.doesNotMatch(
      paper,
      new RegExp(`\\\\${name}(?![A-Za-z])`, "u"),
      `${name} is rendered and must move into the paper-context contract`,
    );
  }

  const completenessRows = paper
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line.startsWith("Partial cells &") ||
        line.startsWith("Canceled cells &"),
    );
  assert.deepEqual(completenessRows, [
    "Partial cells & \\PartialCellCount \\\\",
    "Canceled cells & \\CanceledCellCount \\\\",
  ]);
}

function rebindIntegrityReceipt(receipt: MutableIntegrityReceipt) {
  receipt.upstream.sourceTruthSetSha256 = sha256(
    canonicalJson(receipt.upstream.sourceTruth),
  );
  receipt.upstreamBindingSha256 = sha256(
    canonicalJson(receipt.upstream),
  );
  receipt.derivationBindingSha256 = sha256(
    canonicalJson({
      generatorSha256: receipt.generator.sha256,
      suiteIndexSha256: receipt.upstream.suiteIndex.sha256,
      upstreamBindingSha256: receipt.upstreamBindingSha256,
      outputSetSha256: receipt.outputSetSha256,
    }),
  );
  const { receiptSha256: _receiptSha256, ...unsigned } = receipt;
  receipt.receiptSha256 = sha256(canonicalJson(unsigned));
}

async function rewriteSummaryAndReceipt(
  directory: string,
  summary: SummaryDocument,
) {
  const outputs = renderSummaryBundle(summary);
  for (const [fileName, content] of outputs) {
    await fs.writeFile(path.join(directory, fileName), content, "utf8");
  }
  const receiptPath = path.join(directory, "integrity-receipt.json");
  const receipt = JSON.parse(
    await fs.readFile(receiptPath, "utf8"),
  ) as IntegrityReceipt;
  const outputBindings: DigestBinding[] = [];
  for (const fileName of SUMMARY_OUTPUT_FILES) {
    const content = await fs.readFile(path.join(directory, fileName));
    outputBindings.push({
      path: fileName,
      bytes: content.byteLength,
      sha256: sha256(content),
    });
  }
  outputBindings.sort((left, right) => left.path.localeCompare(right.path));
  receipt.suiteId = summary.suiteId;
  receipt.outputBindings = outputBindings;
  receipt.outputSetSha256 = sha256(canonicalJson(outputBindings));
  const boundReceipt = receipt as IntegrityReceipt & {
    generator: DigestBinding;
    upstream: { suiteIndex: { sha256: string } };
    derivationBindingSha256: string;
  };
  boundReceipt.derivationBindingSha256 = sha256(
    canonicalJson({
      generatorSha256: boundReceipt.generator.sha256,
      suiteIndexSha256: boundReceipt.upstream.suiteIndex.sha256,
      upstreamBindingSha256: boundReceipt.upstreamBindingSha256,
      outputSetSha256: boundReceipt.outputSetSha256,
    }),
  );
  const { receiptSha256: _receiptSha256, ...unsigned } = receipt;
  receipt.receiptSha256 = sha256(canonicalJson(unsigned));
  await fs.writeFile(
    receiptPath,
    `${JSON.stringify(receipt, null, 2)}\n`,
    "utf8",
  );
}

function renderSummaryBundle(summary: SummaryDocument) {
  return new Map<string, string>([
    ["summary.json", `${JSON.stringify(summary, null, 2)}\n`],
    ["metrics.csv", renderMetricsCsv(summary)],
    ["metrics.md", renderMetricsMarkdown(summary)],
    ["completeness.csv", renderCompletenessCsv(summary)],
    ["cost.csv", renderCostCsv(summary)],
    ["metrics-table.tex", renderMetricsLatex(summary)],
    ["cost-table.tex", renderCostLatex(summary)],
  ]);
}

function renderMetricsCsv(summary: SummaryDocument) {
  const rows: Array<Array<string | number>> = [
    [
      "mode",
      "scope",
      "vulnerability_class",
      "precision",
      "recall",
      "f1",
      "true_positive",
      "false_positive",
      "false_negative",
      "class_macro_f1",
      "class_weighted_f1",
      "evidence_caveat",
    ],
  ];
  for (const mode of summary.modes) {
    const overall = mode as ModeSummary & {
      metrics: ModeSummary["metrics"] & {
        truePositive: number;
        falsePositive: number;
        falseNegative: number;
      };
      classMetrics: Array<
        ModeSummary["classMetrics"][number] & {
          vulnerabilityClass: string;
          precision: number;
          recall: number;
          truePositive: number;
          falsePositive: number;
          falseNegative: number;
        }
      >;
    };
    rows.push([
      overall.mode,
      "overall",
      "",
      numberText(overall.metrics.precision),
      numberText(overall.metrics.recall),
      numberText(overall.metrics.f1),
      overall.metrics.truePositive,
      overall.metrics.falsePositive,
      overall.metrics.falseNegative,
      numberText(overall.metrics.classMacroF1),
      numberText(overall.metrics.classWeightedF1),
      overall.evidenceCaveat,
    ]);
    for (const metric of overall.classMetrics) {
      rows.push([
        overall.mode,
        "class",
        metric.vulnerabilityClass,
        numberText(metric.precision),
        numberText(metric.recall),
        numberText(metric.f1),
        metric.truePositive,
        metric.falsePositive,
        metric.falseNegative,
        "",
        "",
        "",
      ]);
    }
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderCompletenessCsv(summary: SummaryDocument) {
  const rows: Array<Array<string | number>> = [
    [
      "mode",
      "completeness_status",
      "planned_components",
      "completed_components",
      "failed_components",
      "skipped_components",
      "component_completion_rate",
      "eligible_files",
      "inspected_files",
      "file_coverage",
      "inspected_bytes",
      "unsupported_language_count",
      "degraded_case_count",
      "degradation_reason_count",
      "status_success",
      "status_partial",
      "status_degraded",
      "status_canceled",
      "status_failed",
    ],
  ];
  for (const mode of summary.modes) {
    const completeness = mode.completeness as ModeSummary["completeness"] & {
      eligibleFiles: number | null;
      inspectedFiles: number | null;
      inspectedBytes: number;
    };
    rows.push([
      mode.mode,
      completeness.status,
      completeness.plannedComponentCount,
      completeness.completedComponentCount,
      completeness.failedComponentCount,
      completeness.skippedComponentCount,
      numberText(completeness.componentCompletionRate),
      nullableText(completeness.eligibleFiles),
      nullableText(completeness.inspectedFiles),
      nullableText(completeness.fileCoverage),
      completeness.inspectedBytes,
      completeness.unsupportedLanguageCount,
      mode.degradation.affectedCaseCount,
      mode.degradation.reasonCount,
      mode.statusCounts.success,
      mode.statusCounts.partial,
      mode.statusCounts.degraded,
      mode.statusCounts.canceled,
      mode.statusCounts.failed,
    ]);
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderCostCsv(summary: SummaryDocument) {
  const rows: Array<Array<string | number>> = [
    [
      "mode",
      "physical_cost_usd",
      "conservative_committed_usd",
      "attributed_cost_usd",
      "physical_tokens",
      "attributed_tokens",
      "physical_model_calls",
      "attributed_model_calls",
      "physical_cells",
      "derived_cells",
    ],
  ];
  for (const mode of summary.modes) {
    const cost = mode.cost as ModeSummary["cost"] & {
      actualPhysicalSpendUsd: number;
      conservativeCommittedUsd: number;
      physicalTokens: number;
      attributedTokens: number;
      physicalModelCalls: number;
      attributedModelCalls: number;
      physicalCellCount: number;
      derivedCellCount: number;
    };
    rows.push([
      mode.mode,
      numberText(cost.actualPhysicalSpendUsd),
      numberText(cost.conservativeCommittedUsd),
      numberText(cost.attributedCostUsd),
      cost.physicalTokens,
      cost.attributedTokens,
      cost.physicalModelCalls,
      cost.attributedModelCalls,
      cost.physicalCellCount,
      cost.derivedCellCount,
    ]);
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderMetricsMarkdown(summary: SummaryDocument) {
  const lines = [
    "# Seven-mode experiment metrics",
    "",
    `Suite: \`${markdownInline(summary.suiteId)}\``,
    "",
    "> Counts and ratios are recomputed from per-case match evidence. Metrics remain visible for incomplete runs, but the evidence caveat must be considered before comparison.",
    "",
    "| Mode | Precision | Recall | F1 | TP | FP | FN | Class macro F1 | Class weighted F1 | Evidence caveat |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
  ];
  for (const mode of summary.modes) {
    const metrics = mode.metrics as ModeSummary["metrics"] & {
      truePositive: number;
      falsePositive: number;
      falseNegative: number;
    };
    const label = (mode as ModeSummary & { label: string }).label;
    lines.push(
      `| ${markdownCell(label)} | ${metrics.precision.toFixed(3)} | ${metrics.recall.toFixed(3)} | ${metrics.f1.toFixed(3)} | ${metrics.truePositive} | ${metrics.falsePositive} | ${metrics.falseNegative} | ${metrics.classMacroF1.toFixed(3)} | ${metrics.classWeightedF1.toFixed(3)} | ${markdownCell(mode.evidenceCaveat)} |`,
    );
  }
  lines.push(
    "",
    "## Per-class metrics",
    "",
    "| Mode | Vulnerability class | Precision | Recall | F1 | TP | FP | FN |",
    "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  );
  for (const mode of summary.modes) {
    const label = (mode as ModeSummary & { label: string }).label;
    const classMetrics = mode.classMetrics as Array<
      ModeSummary["classMetrics"][number] & {
        vulnerabilityClass: string;
        precision: number;
        recall: number;
        truePositive: number;
        falsePositive: number;
        falseNegative: number;
      }
    >;
    if (classMetrics.length === 0) {
      lines.push(`| ${markdownCell(label)} | None | - | - | - | 0 | 0 | 0 |`);
      continue;
    }
    for (const metric of classMetrics) {
      lines.push(
        `| ${markdownCell(label)} | ${markdownCell(metric.vulnerabilityClass)} | ${metric.precision.toFixed(3)} | ${metric.recall.toFixed(3)} | ${metric.f1.toFixed(3)} | ${metric.truePositive} | ${metric.falsePositive} | ${metric.falseNegative} |`,
      );
    }
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function renderMetricsLatex(summary: SummaryDocument) {
  const lines = [
    "% Generated deterministically by Hermsec. Values are proportions.",
    "% Counts and ratios are recomputed from immutable per-case match evidence.",
    "% Evidence caveats identify partial, degraded, canceled, or failed cells.",
    "\\begin{tabular}{lrrrrrrrrl}",
    "\\hline",
    "Mode & Precision & Recall & F1 & TP & FP & FN & Macro F1 & Weighted F1 & Evidence caveat \\\\",
    "\\hline",
  ];
  for (const mode of summary.modes) {
    const label = (mode as ModeSummary & { label: string }).label;
    const metrics = mode.metrics as ModeSummary["metrics"] & {
      truePositive: number;
      falsePositive: number;
      falseNegative: number;
    };
    lines.push(
      `${latexEscape(label)} & ${metrics.precision.toFixed(3)} & ${metrics.recall.toFixed(3)} & ${metrics.f1.toFixed(3)} & ${metrics.truePositive} & ${metrics.falsePositive} & ${metrics.falseNegative} & ${metrics.classMacroF1.toFixed(3)} & ${metrics.classWeightedF1.toFixed(3)} & ${latexEscape(mode.evidenceCaveat)} \\\\`,
    );
  }
  lines.push(
    "\\hline",
    "\\end{tabular}",
    "",
    "% Per-class metrics",
    "\\begin{tabular}{llrrrrrr}",
    "\\hline",
    "Mode & Class & Precision & Recall & F1 & TP & FP & FN \\\\",
    "\\hline",
  );
  for (const mode of summary.modes) {
    const label = (mode as ModeSummary & { label: string }).label;
    const classMetrics = mode.classMetrics as Array<
      ModeSummary["classMetrics"][number] & {
        vulnerabilityClass: string;
        precision: number;
        recall: number;
        truePositive: number;
        falsePositive: number;
        falseNegative: number;
      }
    >;
    for (const metric of classMetrics) {
      lines.push(
        `${latexEscape(label)} & ${latexEscape(metric.vulnerabilityClass)} & ${metric.precision.toFixed(3)} & ${metric.recall.toFixed(3)} & ${metric.f1.toFixed(3)} & ${metric.truePositive} & ${metric.falsePositive} & ${metric.falseNegative} \\\\`,
      );
    }
  }
  lines.push("\\hline", "\\end{tabular}", "");
  return `${lines.join("\n")}\n`;
}

function renderCostLatex(summary: SummaryDocument) {
  const lines = [
    "% Generated deterministically by Hermsec.",
    "\\begin{tabular}{lrrrrrr}",
    "\\hline",
    "Mode & Physical USD & Attributed USD & Physical tokens & Attributed tokens & Physical calls & Attributed calls \\\\",
    "\\hline",
  ];
  for (const mode of summary.modes) {
    const label = (mode as ModeSummary & { label: string }).label;
    const cost = mode.cost as ModeSummary["cost"] & {
      actualPhysicalSpendUsd: number;
      physicalTokens: number;
      attributedTokens: number;
      physicalModelCalls: number;
      attributedModelCalls: number;
    };
    lines.push(
      `${latexEscape(label)} & ${cost.actualPhysicalSpendUsd.toFixed(6)} & ${cost.attributedCostUsd.toFixed(6)} & ${cost.physicalTokens} & ${cost.attributedTokens} & ${cost.physicalModelCalls} & ${cost.attributedModelCalls} \\\\`,
    );
  }
  lines.push("\\hline", "\\end{tabular}", "");
  return `${lines.join("\n")}\n`;
}

async function readSummary(directory: string) {
  return JSON.parse(
    await fs.readFile(path.join(directory, "summary.json"), "utf8"),
  ) as SummaryDocument;
}

function runExporter(
  summaryDirectory: string,
  suiteDirectory: string,
  outputDirectory: string,
) {
  return runNode(EXPORTER, [
    "--summary",
    summaryDirectory,
    "--suite",
    suiteDirectory,
    "--out",
    outputDirectory,
  ]);
}

function runNode(script: string, arguments_: string[]) {
  return new Promise<{
    code: number | null;
    stdout: string;
    stderr: string;
  }>((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...arguments_], {
      cwd: REPOSITORY_ROOT,
      env: {
        PATH: process.env.PATH,
        SystemRoot: process.env.SystemRoot,
        TEMP: process.env.TEMP,
        TMP: process.env.TMP,
      },
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
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function temporaryRoot(t: TestContext, prefix: string) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

async function copyDirectory(source: string, destination: string) {
  await fs.cp(source, destination, {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
}

async function createDirectoryLink(target: string, linkPath: string) {
  await fs.symlink(
    target,
    linkPath,
    process.platform === "win32" ? "junction" : "dir",
  );
}

async function listTree(root: string, relative = ""): Promise<string[]> {
  const entries = await fs.readdir(path.join(root, relative), {
    withFileTypes: true,
  });
  const output: string[] = [];
  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name, "en"),
  )) {
    const entryPath = relative
      ? `${relative}/${entry.name}`
      : entry.name;
    if (entry.isDirectory()) {
      output.push(`${entryPath}/`);
      output.push(...(await listTree(root, entryPath)));
    } else {
      output.push(entryPath);
    }
  }
  return output;
}

function csvRow(values: Array<string | number>) {
  return values.map(csvCell).join(",");
}

function csvCell(value: string | number) {
  let text = String(value);
  if (/^[=+@-]/u.test(text)) {
    text = `'${text}`;
  }
  if (/[",\r\n]/u.test(text)) {
    return `"${text.replaceAll('"', '""')}"`;
  }
  return text;
}

function numberText(value: number) {
  if (Number.isInteger(value)) {
    return String(value);
  }
  return value.toFixed(12).replace(/0+$/u, "").replace(/\.$/u, "");
}

function nullableText(value: number | null) {
  return value === null ? "" : numberText(value);
}

function markdownCell(value: string) {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replace(/\r?\n/gu, " ");
}

function markdownInline(value: string) {
  return value.replaceAll("`", "\\`");
}

function latexEscape(value: string) {
  const replacements: Record<string, string> = {
    "\\": "\\textbackslash{}",
    "&": "\\&",
    "%": "\\%",
    "$": "\\$",
    "#": "\\#",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "~": "\\textasciitilde{}",
    "^": "\\textasciicircum{}",
  };
  return [...value]
    .map((character) => replacements[character] ?? character)
    .join("");
}

function sha256(value: string | Buffer) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown) {
  return JSON.stringify(canonicalize(value));
}

function prettyCanonicalJson(value: unknown) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object)
        .sort()
        .map((key) => [key, canonicalize(object[key])]),
    );
  }
  return value;
}
