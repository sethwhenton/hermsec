import assert from "node:assert/strict";
import test from "node:test";
import {
  categoryMatrix,
  computeCategoryMetrics,
  computeMetrics,
  MATCH_ASSIGNMENT_FINDING_LIMIT,
  MATCH_RAW_INPUT_FINDING_LIMIT,
  MatchAssignmentCapacityError,
  MatchRawInputCapacityError,
  matchFindings,
  maximumWeightOneToOne,
  normalizeCve,
  normalizeEvalPath,
  projectFinding,
  scoreCandidate,
  type ActualFindingProjection,
  type GroundTruthFinding,
} from "../../../src/eval/index.js";
import type { Finding } from "../../../src/shared/types.js";

test("evaluation matcher accepts compatible class and concrete location evidence", () => {
  const candidate = scoreCandidate(
    makeCodeGroundTruth(),
    makeActualCodeFinding(),
  );

  assert.equal(candidate.expectedId, "GT-CODE-SQLI");
  assert.equal(candidate.actualFingerprint, "actual-code-sqli");
  assert.equal(candidate.eligible, true);
  assert.ok(candidate.evidenceScore >= 60);
  assert.deepEqual(candidate.rejectionReasons, []);
  assert.equal(
    candidate.signals.find((signal) => signal.name === "severity")?.points,
    0,
  );
});

test("severity cannot rescue a category, class, or location mismatch", () => {
  const expected = makeCodeGroundTruth();
  const wrongCategory = scoreCandidate(expected, {
    ...makeActualCodeFinding(),
    category: "config",
  });
  const wrongClass = scoreCandidate(expected, {
    ...makeActualCodeFinding(),
    title: "Possible command injection",
    cwe: ["CWE-78"],
    vulnerabilityClass: "command-injection",
    ruleIds: ["semgrep.command-injection"],
  });
  const wrongLocation = scoreCandidate(expected, {
    ...makeActualCodeFinding(),
    location: { path: "src/unrelated.js", startLine: 14 },
  });

  assert.equal(wrongCategory.eligible, false);
  assert.ok(wrongCategory.rejectionReasons.includes("category-mismatch"));
  assert.equal(wrongClass.eligible, false);
  assert.ok(
    wrongClass.rejectionReasons.includes("vulnerability-class-mismatch"),
  );
  assert.equal(wrongLocation.eligible, false);
  assert.ok(
    wrongLocation.rejectionReasons.includes("location-evidence-mismatch"),
  );
  assert.equal(
    matchFindings([expected], [
      { ...wrongCategoryToActual(wrongCategory), severity: "high" },
      { ...wrongCategoryToActual(wrongClass), severity: "high" },
      { ...wrongCategoryToActual(wrongLocation), severity: "high" },
    ]).matches.length,
    0,
  );
});

test("severity disagreement remains a valid detection match", () => {
  const result = matchFindings(
    [makeCodeGroundTruth()],
    [{ ...makeActualCodeFinding(), severity: "info" }],
  );

  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0]?.evidenceScore, result.matches[0]?.score);
});

test("source-and-sink truth requires compatible source evidence", () => {
  const expected: GroundTruthFinding = {
    ...makeCodeGroundTruth(),
    evidence: {
      type: "source-and-sink",
      sourceLocations: [{ path: "src/routes/search.js", startLine: 5 }],
    },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "required",
      evidence: "source-and-sink",
    },
  };
  const withoutSource = matchFindings([expected], [makeActualCodeFinding()]);
  const withSource = matchFindings(
    [expected],
    [
      {
        ...makeActualCodeFinding(),
        sourceLocations: [{ path: "src/routes/search.js", startLine: 5 }],
      },
    ],
  );

  assert.equal(withoutSource.matches.length, 0);
  assert.ok(
    withoutSource.rejectedCandidates[0]?.rejectionReasons.includes(
      "source-evidence-mismatch",
    ),
  );
  assert.equal(withSource.matches.length, 1);
});

test("source-and-sink evidence honors each truth finding's zero line tolerance", () => {
  const expected: GroundTruthFinding = {
    ...makeCodeGroundTruth(),
    location: { path: "src/routes/search.js", startLine: 14 },
    evidence: {
      type: "source-and-sink",
      sourceLocations: [{ path: "src/routes/input.js", startLine: 5 }],
    },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "required",
      evidence: "source-and-sink",
    },
    matchHints: {
      ...makeCodeGroundTruth().matchHints,
      lineTolerance: 0,
    },
  };
  const actual: ActualFindingProjection = {
    ...makeActualCodeFinding(),
    location: { path: "src/routes/search.js", startLine: 14 },
    sourceLocations: [{ path: "src/routes/input.js", startLine: 8 }],
  };

  const exactResult = matchFindings([expected], [actual]);
  const relaxedResult = matchFindings(
    [
      {
        ...expected,
        matchHints: { ...expected.matchHints, lineTolerance: 3 },
      },
    ],
    [actual],
  );

  assert.equal(exactResult.matches.length, 0);
  assert.ok(
    exactResult.rejectedCandidates[0]?.rejectionReasons.includes(
      "source-evidence-mismatch",
    ),
  );
  assert.equal(relaxedResult.matches.length, 1);
});

test("shared Finding source locations project and match source-and-sink truth end to end", () => {
  const expected: GroundTruthFinding = {
    ...makeCodeGroundTruth(),
    evidence: {
      type: "source-and-sink",
      sourceLocations: [{ path: "src/routes/input.js", startLine: 4 }],
    },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "required",
      evidence: "source-and-sink",
    },
  };
  const finding: Finding = {
    id: "FINDING-SOURCE-SINK",
    fingerprint: "source-sink-fingerprint",
    title: "SQL injection",
    category: "code",
    severity: "high",
    confidence: "high",
    description: "Untrusted input reaches a SQL query.",
    evidence: "request input reaches query",
    remediation: "Use a parameterized query.",
    tool: "semgrep",
    ruleId: "semgrep.sql-injection",
    cwe: ["CWE-89"],
    location: { file: "src/routes/search.js", startLine: 14 },
    sourceLocations: [{ file: "src/routes/input.js", startLine: 4 }],
  };

  const projected = projectFinding(finding);
  const result = matchFindings([expected], [projected]);

  assert.deepEqual(projected.sourceLocations, [
    { path: "src/routes/input.js", startLine: 4 },
  ]);
  assert.equal(result.matches.length, 1);
});

test("explicit optional location and line policies do not require location evidence", () => {
  const expected: GroundTruthFinding = {
    ...makeCodeGroundTruth(),
    evidence: { type: "primary-location" },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "optional",
      line: "optional",
      evidence: "primary-location",
    },
  };
  const actual: ActualFindingProjection = { ...makeActualCodeFinding() };
  delete actual.location;

  const result = matchFindings([expected], [actual]);

  assert.equal(result.matches.length, 1);
  assert.ok(
    !result.rejectedCandidates.some((candidate) =>
      candidate.rejectionReasons.includes("location-evidence-mismatch"),
    ),
  );
});

test("a required location with an optional line accepts path-only evidence", () => {
  const expected: GroundTruthFinding = {
    ...makeCodeGroundTruth(),
    evidence: { type: "primary-location" },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "optional",
      evidence: "primary-location",
    },
  };
  const actual = {
    ...makeActualCodeFinding(),
    location: { path: "src/routes/search.js" },
  };

  assert.equal(matchFindings([expected], [actual]).matches.length, 1);
});

test("maximum-weight assignment finds the global optimum rather than a greedy pair", () => {
  const assignment = maximumWeightOneToOne([
    [9, 8],
    [8, 0],
  ]);

  assert.deepEqual(assignment, [
    [0, 1],
    [1, 0],
  ]);
});

test("maximum-weight assignment is deterministic across equal scores", () => {
  const first = maximumWeightOneToOne([
    [10, 10],
    [10, 10],
  ]);
  const second = maximumWeightOneToOne([
    [10, 10],
    [10, 10],
  ]);

  assert.deepEqual(first, second);
  assert.deepEqual(first, [
    [0, 0],
    [1, 1],
  ]);
});

test("maximum-weight assignment agrees with brute force on bounded rectangular matrices", () => {
  let state = 0x5eed1234;
  const nextWeight = () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state % 11;
  };

  for (let rowCount = 1; rowCount <= 4; rowCount += 1) {
    for (let columnCount = 1; columnCount <= 4; columnCount += 1) {
      for (let sample = 0; sample < 12; sample += 1) {
        const weights = Array.from({ length: rowCount }, () =>
          Array.from({ length: columnCount }, nextWeight),
        );
        const assignment = maximumWeightOneToOne(weights);
        const actualWeight = assignment.reduce(
          (total, [row, column]) =>
            total + (weights[row]?.[column] ?? 0),
          0,
        );

        assert.equal(actualWeight, bruteForceMaximumWeight(weights));
      }
    }
  }
});

test("evaluation metrics report finding-level precision, recall, and F1", () => {
  const expected: GroundTruthFinding[] = [
    makeCodeGroundTruth(),
    {
      ...makeCodeGroundTruth(),
      id: "GT-CODE-CMD",
      vulnerabilityClass: "command-injection",
      cwe: ["CWE-78"],
      title: "Command injection",
      location: { path: "src/routes/search.js", startLine: 50 },
      ruleIds: ["semgrep.command-injection"],
    },
  ];
  const actual: ActualFindingProjection[] = [
    makeActualCodeFinding(),
    {
      ...makeActualCodeFinding(),
      id: "ACTUAL-SPURIOUS",
      fingerprint: "actual-spurious",
      title: "Spurious weak cryptography finding",
      vulnerabilityClass: "weak-cryptography",
      severity: "low",
      cwe: ["CWE-327"],
      location: { path: "src/other.js", startLine: 5 },
      ruleIds: ["semgrep.weak-crypto"],
    },
  ];

  const result = matchFindings(expected, actual);
  const metrics = computeMetrics(result);

  assert.equal(result.matches.length, 1);
  assert.equal(result.falsePositives.length, 1);
  assert.equal(result.falseNegatives.length, 1);
  assert.equal(metrics.precision, 0.5);
  assert.equal(metrics.recall, 0.5);
  assert.equal(metrics.f1, 0.5);
});

test("evaluation matcher classifies duplicate actual findings as ignored noise", () => {
  const result = matchFindings(
    [makeCodeGroundTruth()],
    [
      makeActualCodeFinding(),
      {
        ...makeActualCodeFinding(),
        id: "ACTUAL-CODE-SQLI-DUPLICATE",
        severity: "medium",
      },
    ],
  );
  const metrics = computeMetrics(result);

  assert.equal(result.matches.length, 1);
  assert.equal(result.falsePositives.length, 0);
  assert.equal(result.ignoredActual.length, 1);
  assert.equal(metrics.duplicateCount, 1);
  assert.equal(metrics.duplicateRate, 0.5);
});

test("severity swaps do not change recall or collapse incompatible vulnerability classes", () => {
  const expected = [makeCodeGroundTruth()];
  const compatible = makeSharedIdentityClassFinding(
    "ACTUAL-COMPATIBLE",
    "sql-injection",
    "low",
  );
  const incompatible = makeSharedIdentityClassFinding(
    "ACTUAL-INCOMPATIBLE",
    "command-injection",
    "critical",
  );
  const incompatibleHigher = matchFindings(expected, [
    compatible,
    incompatible,
  ]);
  const compatibleHigher = matchFindings(expected, [
    { ...compatible, severity: "critical" },
    { ...incompatible, severity: "low" },
  ]);

  for (const result of [incompatibleHigher, compatibleHigher]) {
    const metrics = computeMetrics(result);
    assert.equal(metrics.recall, 1);
    assert.equal(result.matches.length, 1);
    assert.equal(result.matches[0]?.actualId, "ACTUAL-COMPATIBLE");
    assert.equal(result.falsePositives.length, 1);
    assert.equal(
      result.falsePositives[0]?.id,
      "ACTUAL-INCOMPATIBLE",
    );
    assert.equal(result.ignoredActual.length, 0);
  }
});

test("true duplicate representative selection is deterministic and severity-free", () => {
  const canonical = makeSharedIdentityClassFinding(
    "ACTUAL-A-CANONICAL",
    "sql-injection",
    "low",
  );
  const duplicate = makeSharedIdentityClassFinding(
    "ACTUAL-Z-DUPLICATE",
    "sql-injection",
    "critical",
  );
  const duplicateHigher = matchFindings(
    [makeCodeGroundTruth()],
    [canonical, duplicate],
  );
  const canonicalHigher = matchFindings(
    [makeCodeGroundTruth()],
    [
      { ...canonical, severity: "critical" },
      { ...duplicate, severity: "low" },
    ],
  );

  for (const result of [duplicateHigher, canonicalHigher]) {
    assert.equal(computeMetrics(result).recall, 1);
    assert.equal(result.matches[0]?.actualId, "ACTUAL-A-CANONICAL");
    assert.equal(result.ignoredActual.length, 1);
    assert.equal(
      result.ignoredActual[0]?.duplicateOfId,
      "ACTUAL-A-CANONICAL",
    );
  }
});

test("dedupe and assignment retain distinct source-to-sink flows sharing a fingerprint", () => {
  const expected = [
    sourceFlowTruth("FLOW-A", "src/source-a.js"),
    sourceFlowTruth("FLOW-B", "src/source-b.js"),
  ];
  const actual = [
    sourceFlowActual("ACTUAL-A", "src/source-a.js"),
    sourceFlowActual("ACTUAL-B", "src/source-b.js"),
  ];

  const result = matchFindings(expected, actual);

  assert.equal(result.matches.length, 2);
  assert.equal(result.falsePositives.length, 0);
  assert.equal(result.falseNegatives.length, 0);
  assert.equal(result.ignoredActual.length, 0);
});

test("181 distinct findings sharing one CWE remain distinct", () => {
  const expected = Array.from({ length: 181 }, (_, index) => ({
    ...makeCodeGroundTruth(),
    id: `GT-SQLI-${index.toString().padStart(3, "0")}`,
    location: { path: "src/large.js", startLine: index * 10 + 1 },
  }));
  const actual = Array.from({ length: 181 }, (_, index) => ({
    ...makeActualCodeFinding(),
    id: `ACTUAL-SQLI-${index.toString().padStart(3, "0")}`,
    fingerprint: `actual-sqli-${index.toString().padStart(3, "0")}`,
    location: { path: "src/large.js", startLine: index * 10 + 1 },
  }));

  const result = matchFindings(expected, actual);

  assert.equal(result.matches.length, 181);
  assert.equal(result.falsePositives.length, 0);
  assert.equal(result.falseNegatives.length, 0);
  assert.equal(result.ignoredActual.length, 0);
});

test("raw capacity rejects oversized arrays before reading or sorting their elements", () => {
  const oversizedExpected = new Array<GroundTruthFinding>(
    MATCH_RAW_INPUT_FINDING_LIMIT + 1,
  );
  Object.defineProperty(oversizedExpected, 0, {
    get: () => {
      throw new Error("raw expected input was touched");
    },
  });
  const oversizedActual = new Array<ActualFindingProjection>(
    MATCH_RAW_INPUT_FINDING_LIMIT + 1,
  );
  Object.defineProperty(oversizedActual, 0, {
    get: () => {
      throw new Error("raw actual input was touched");
    },
  });

  for (const invoke of [
    () => matchFindings(oversizedExpected, []),
    () => matchFindings([], oversizedActual),
  ]) {
    assert.throws(
      invoke,
      (error: unknown) =>
        error instanceof MatchRawInputCapacityError &&
        error.code === "eval-raw-input-capacity-exceeded",
    );
  }
});

test("deduplicated assignment retains its separate 256-finding bound", () => {
  const actual = Array.from(
    { length: MATCH_ASSIGNMENT_FINDING_LIMIT + 1 },
    (_, index) => ({
      ...makeActualCodeFinding(),
      id: `ACTUAL-OVER-LIMIT-${index}`,
      fingerprint: `actual-over-limit-${index}`,
      location: { path: "src/large.js", startLine: index + 1 },
    }),
  );

  assert.throws(
    () => matchFindings([], actual),
    (error: unknown) =>
      error instanceof MatchAssignmentCapacityError &&
      error.code === "eval-assignment-capacity-exceeded",
  );
});

test("dependency findings require package and advisory identity", () => {
  const expected: GroundTruthFinding = {
    id: "GT-DEP-LODASH",
    category: "dependency",
    vulnerabilityClass: "known-vulnerable-dependency",
    title: "Vulnerable lodash fixture dependency",
    severity: "high",
    cwe: [],
    identifiers: {
      cve: ["CVE-2021-23337"],
      ghsa: ["GHSA-35jh-r3h4-6jhm"],
      osv: [],
    },
    package: {
      ecosystem: "npm",
      name: "lodash",
      installedVersion: "4.17.20",
    },
    ruleIds: ["npm-audit"],
  };
  const actual: ActualFindingProjection = {
    id: "ACTUAL-DEP-LODASH",
    fingerprint: "actual-dep-lodash",
    category: "dependency",
    vulnerabilityClass: "known-vulnerable-dependency",
    title: "lodash advisory",
    severity: "high",
    cwe: [],
    identifiers: { cve: ["cve-2021-23337"], ghsa: [], osv: [] },
    package: {
      ecosystem: "NPM",
      name: "lodash",
      installedVersion: "4.17.20",
    },
    ruleIds: ["npm-audit"],
  };

  assert.equal(matchFindings([expected], [actual]).matches.length, 1);
  assert.equal(
    matchFindings(
      [expected],
      [{ ...actual, identifiers: { cve: [], ghsa: [], osv: [] } }],
    ).matches.length,
    0,
  );
});

test("normalizers canonicalize identifiers and paths for stable matching", () => {
  assert.equal(normalizeCve("cve_2021_23337"), "CVE-2021-23337");
  assert.equal(
    normalizeEvalPath(
      "E:\\Programming\\Security insider II\\Hermsec Proj\\tests\\fixtures\\repos\\node\\src\\app.js",
    ),
    "E:/Programming/Security insider II/Hermsec Proj/tests/fixtures/repos/node/src/app.js",
  );
});

test("category matrices include missed and spurious buckets", () => {
  const result = matchFindings([makeCodeGroundTruth()], []);
  const matrix = categoryMatrix(result);
  const byCategory = computeCategoryMetrics(result);

  assert.equal(matrix.code?.["<missed>"], 1);
  assert.equal(byCategory.code.falseNegative, 1);
  assert.equal(byCategory.code.recall, 0);
  assert.equal(byCategory.dependency.categorySupport, 0);
});

function makeCodeGroundTruth(): GroundTruthFinding {
  return {
    id: "GT-CODE-SQLI",
    category: "code",
    vulnerabilityClass: "sql-injection",
    title: "SQL injection in fixture search route",
    severity: "high",
    cwe: ["CWE-89"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/routes/search.js", startLine: 14 },
    ruleIds: ["semgrep.sql-injection"],
    matchHints: { lineTolerance: 3 },
  };
}

function makeActualCodeFinding(): ActualFindingProjection {
  return {
    id: "ACTUAL-CODE-SQLI",
    fingerprint: "actual-code-sqli",
    category: "code",
    vulnerabilityClass: "sql-injection",
    title: "Possible SQL injection",
    severity: "high",
    cwe: ["cwe-089"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/routes/search.js", startLine: 15 },
    ruleIds: ["SEMgrep.SQL-Injection"],
    tool: "semgrep",
  };
}

function sourceFlowTruth(
  id: string,
  sourcePath: string,
): GroundTruthFinding {
  return {
    ...makeCodeGroundTruth(),
    id,
    evidence: {
      type: "source-and-sink",
      sourceLocations: [{ path: sourcePath, startLine: 2 }],
    },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "required",
      evidence: "source-and-sink",
    },
  };
}

function sourceFlowActual(
  id: string,
  sourcePath: string,
): ActualFindingProjection {
  return {
    ...makeActualCodeFinding(),
    id,
    fingerprint: "shared-flow-fingerprint",
    sourceLocations: [{ path: sourcePath, startLine: 2 }],
  };
}

function makeSharedIdentityClassFinding(
  id: string,
  vulnerabilityClass: string,
  severity: ActualFindingProjection["severity"],
): ActualFindingProjection {
  return {
    id,
    fingerprint: "shared-class-fingerprint",
    category: "code",
    vulnerabilityClass,
    title: "Untrusted data flow",
    severity,
    cwe: [],
    identifiers: { cve: [], ghsa: [], osv: [] },
    ruleIds: ["shared.detector.rule"],
    location: { path: "src/routes/search.js", startLine: 14 },
    tool: "shared-detector",
  };
}

function wrongCategoryToActual(
  candidate: ReturnType<typeof scoreCandidate>,
): ActualFindingProjection {
  if (candidate.rejectionReasons.includes("category-mismatch")) {
    return { ...makeActualCodeFinding(), category: "config" };
  }
  if (
    candidate.rejectionReasons.includes("vulnerability-class-mismatch")
  ) {
    return {
      ...makeActualCodeFinding(),
      vulnerabilityClass: "command-injection",
      title: "Possible command injection",
      cwe: ["CWE-78"],
      ruleIds: ["semgrep.command-injection"],
    };
  }
  return {
    ...makeActualCodeFinding(),
    location: { path: "src/unrelated.js", startLine: 14 },
  };
}

function bruteForceMaximumWeight(
  weights: readonly (readonly number[])[],
): number {
  const columnCount = weights.reduce(
    (largest, row) => Math.max(largest, row.length),
    0,
  );
  const visit = (row: number, usedColumns: ReadonlySet<number>): number => {
    if (row >= weights.length) {
      return 0;
    }

    let best = visit(row + 1, usedColumns);
    for (let column = 0; column < columnCount; column += 1) {
      const weight = weights[row]?.[column] ?? 0;
      if (weight <= 0 || usedColumns.has(column)) {
        continue;
      }
      const nextUsed = new Set(usedColumns);
      nextUsed.add(column);
      best = Math.max(best, weight + visit(row + 1, nextUsed));
    }
    return best;
  };

  return visit(0, new Set());
}
