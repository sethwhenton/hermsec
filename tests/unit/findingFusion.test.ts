import assert from "node:assert/strict";
import test from "node:test";
import {
  buildStableFindingIdentity,
  normalizeRepositoryPath,
} from "../../src/agent/findingIdentity.js";
import {
  fuseFindings,
  MAX_FINDING_FUSION_INPUTS,
  type FindingFusionInput,
} from "../../src/agent/findingFusion.js";
import type { Finding } from "../../src/shared/types.js";

test("stable identity normalizes equivalent repository paths", () => {
  const base = codeFinding({
    id: "path-a",
    fingerprint: "path-a",
    location: { file: ".\\src\\routes\\search.js", startLine: 14, endLine: 14 },
  });
  const equivalent = codeFinding({
    id: "path-b",
    fingerprint: "path-b",
    location: { file: "src/routes/search.js", startLine: 14, endLine: 14 },
  });

  assert.equal(normalizeRepositoryPath(".\\src\\routes\\search.js"), "src/routes/search.js");
  assert.equal(
    buildStableFindingIdentity(base).groupAnchor,
    buildStableFindingIdentity(equivalent).groupAnchor,
  );
  assert.equal(buildStableFindingIdentity(base).id, buildStableFindingIdentity(equivalent).id);
  assert.equal(
    normalizeRepositoryPath("E:\\Repo\\Src\\APP.js", "e:\\repo"),
    "src/app.js",
  );
  assert.notEqual(
    normalizeRepositoryPath("/repo/Src/App.js", "/repo"),
    normalizeRepositoryPath("/repo/src/App.js", "/repo"),
  );
});

test("ecosystem normalization treats prototype property names as plain data", () => {
  const identity = buildStableFindingIdentity(dependencyFinding({
    package: {
      ecosystem: "__proto__",
      name: "example",
      installedVersion: "1.0.0",
    },
  }));

  assert.equal(identity.dependency?.ecosystem, "__proto__");
  assert.equal(identity.dependency?.name, "example");
});

test("same-CWE findings at different sinks remain separate", () => {
  const first = codeFinding({
    id: "scanner-sql-first",
    fingerprint: "fp-scanner-sql-first",
    location: { file: "src/db.js", startLine: 10, endLine: 10 },
  });
  const second = codeFinding({
    id: "scanner-sql-second",
    fingerprint: "fp-scanner-sql-second",
    location: { file: "src/db.js", startLine: 80, endLine: 80 },
  });

  const result = fuseFindings([
    scannerSource(first, "semgrep:first"),
    scannerSource(second, "semgrep:second"),
  ]);

  assert.equal(result.canonicalFindings.length, 2);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
  assert.deepEqual(
    result.canonicalFindings.map((finding) => finding.location?.startLine),
    [10, 80],
  );
  assert.notEqual(
    result.canonicalFindings[0]?.id,
    result.canonicalFindings[1]?.id,
  );
});

test("distinct nearby sinks do not merge merely because they are within line tolerance", () => {
  const result = fuseFindings([
    scannerSource(codeFinding({
      id: "sink-line-10",
      fingerprint: "fp-sink-line-10",
      evidence: "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
      location: { file: "src/db.js", startLine: 10, endLine: 10 },
    }), "scanner:line-10"),
    scannerSource(codeFinding({
      id: "sink-line-13",
      fingerprint: "fp-sink-line-13",
      evidence: "db.query(`SELECT * FROM invoices WHERE id = ${invoiceId}`)",
      location: { file: "src/db.js", startLine: 13, endLine: 13 },
    }), "scanner:line-13"),
  ], { lineTolerance: 3 });

  assert.equal(result.canonicalFindings.length, 2);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
});

test("reused fingerprints do not merge located findings with different sink anchors", () => {
  const result = fuseFindings([
    scannerSource(codeFinding({
      id: "reused-fingerprint-users",
      fingerprint: "fp-reused-by-scanner",
      evidence: "db.query(userSql)",
      location: { file: "src/db.js", startLine: 40, endLine: 40 },
    }), "scanner:reused-users"),
    scannerSource(codeFinding({
      id: "reused-fingerprint-invoices",
      fingerprint: "fp-reused-by-scanner",
      evidence: "db.query(invoiceSql)",
      location: { file: "src/db.js", startLine: 41, endLine: 41 },
    }), "scanner:reused-invoices"),
  ], { lineTolerance: 3 });

  assert.equal(result.canonicalFindings.length, 2);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
  assert.deepEqual(
    result.canonicalFindings
      .map((finding) => finding.location?.startLine)
      .sort((left, right) => (left ?? 0) - (right ?? 0)),
    [40, 41],
  );
});

test("same-text adjacent physical sinks remain distinct despite a reused fingerprint", () => {
  const result = fuseFindings([
    scannerSource(codeFinding({
      id: "adjacent-same-sink-first",
      fingerprint: "fp-reused-adjacent-sink",
      evidence: "db.query(userSql)",
      location: { file: "src/db.js", startLine: 40, endLine: 40 },
    }), "scanner:adjacent-first"),
    scannerSource(codeFinding({
      id: "adjacent-same-sink-second",
      fingerprint: "fp-reused-adjacent-sink",
      evidence: "db.query(userSql)",
      location: { file: "src/db.js", startLine: 41, endLine: 41 },
    }), "scanner:adjacent-second"),
  ], { lineTolerance: 20 });

  assert.equal(result.canonicalFindings.length, 2);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
  assert.deepEqual(
    result.canonicalFindings
      .map((finding) => finding.location?.startLine)
      .sort((left, right) => (left ?? 0) - (right ?? 0)),
    [40, 41],
  );
  assert.notEqual(
    result.canonicalFindings[0]?.id,
    result.canonicalFindings[1]?.id,
  );
});

test("exact repository duplicates still merge without a location", () => {
  const first = codeFinding({
    id: "unlocated-first",
    fingerprint: "fp-unlocated-exact",
  });
  const second = codeFinding({
    id: "unlocated-second",
    fingerprint: "fp-unlocated-exact",
    tool: "hermsec-agent",
  });
  delete first.location;
  delete second.location;

  const result = fuseFindings([
    scannerSource(first, "scanner:unlocated"),
    agentSource(second, "agent:unlocated"),
  ]);

  assert.equal(result.canonicalFindings.length, 1);
  assert.deepEqual(result.sidecar.duplicateGroups[0]?.sourceIds, [
    "agent:unlocated",
    "scanner:unlocated",
  ]);
});

test("scanner and agent duplicates fuse without losing scanner evidence", () => {
  const scanner = codeFinding({
    id: "scanner-sql",
    fingerprint: "fp-scanner-sql",
    severity: "high",
    confidence: "confirmed",
    tool: "semgrep",
    evidence: "Semgrep matched db.query(req.query.id) at the SQL query sink.",
    location: { file: "src/db.js", startLine: 22, endLine: 22 },
  });
  const agent = codeFinding({
    id: "agent-sql",
    fingerprint: "fp-agent-sql",
    severity: "critical",
    confidence: "high",
    tool: "hermsec-agent",
    evidence: "Agent data flow reaches db.query(req.query.id) at the sink.",
    cwe: ["CWE-20", "CWE-89"],
    location: { file: "./src/db.js", startLine: 20, endLine: 22 },
    agent: {
      mode: "single-agent",
      source: "single-agent",
      provider: "test",
      generatedAt: "2026-07-25T00:00:00.000Z",
    },
  });

  const result = fuseFindings([
    scannerSource(scanner, "scanner:semgrep"),
    agentSource(agent, "agent:single"),
  ]);
  const scannerOnly = fuseFindings([
    scannerSource(scanner, "scanner:semgrep"),
  ]);

  assert.equal(result.canonicalFindings.length, 1);
  assert.equal(result.canonicalFindings[0]?.tool, "semgrep");
  assert.equal(result.canonicalFindings[0]?.evidence, scanner.evidence);
  assert.equal(result.canonicalFindings[0]?.severity, "critical");
  assert.equal(result.canonicalFindings[0]?.confidence, "high");
  assert.equal(result.canonicalFindings[0]?.id, scannerOnly.canonicalFindings[0]?.id);
  assert.equal(result.canonicalFindings[0]?.fingerprint, scannerOnly.canonicalFindings[0]?.fingerprint);
  assert.equal(
    [scanner, agent].some((finding) =>
      finding.severity === result.canonicalFindings[0]?.severity &&
      finding.confidence === result.canonicalFindings[0]?.confidence
    ),
    true,
  );
  assert.deepEqual(result.sidecar.canonicalSources[0]?.sourceIds, [
    "agent:single",
    "scanner:semgrep",
  ]);
  assert.deepEqual(result.sidecar.canonicalSources[0]?.sourceLabels, [
    "Semgrep",
    "Single agent",
  ]);
  assert.deepEqual(result.sidecar.canonicalSources[0]?.scannerSourceIds, [
    "scanner:semgrep",
  ]);
  assert.equal(result.sidecar.duplicateGroups[0]?.reason, "compatible-repository-sink");
});

test("canonical identity is stable when a more specific corroborator becomes representative", () => {
  const base = codeFinding({
    id: "identity-base",
    fingerprint: "fp-identity-base",
    evidence: "Semgrep matched db.query(req.query.id) at the sink.",
    cwe: ["CWE-89"],
    location: { file: "src/db.js", startLine: 20 },
  });
  delete base.ruleId;
  const enriched = codeFinding({
    id: "identity-enriched",
    fingerprint: "fp-identity-enriched",
    evidence: "A traced request reaches db.query(req.query.id) at the same sink.",
    ruleId: "javascript.express.sql-injection",
    cwe: ["CWE-20", "CWE-89"],
    identifiers: {
      cve: ["CVE-2026-12345"],
      ghsa: ["GHSA-AAAA-BBBB-CCCC"],
    },
    location: { file: "./src/db.js", startLine: 20, endLine: 22 },
  });

  const baseOnly = fuseFindings([
    scannerSource(base, "scanner:identity-base"),
  ]);
  const corroborated = fuseFindings([
    scannerSource(base, "scanner:identity-base"),
    scannerSource(enriched, "scanner:identity-enriched"),
  ]);

  assert.equal(corroborated.canonicalFindings.length, 1);
  assert.equal(corroborated.canonicalFindings[0]?.evidence, enriched.evidence);
  assert.deepEqual(corroborated.canonicalFindings[0]?.cwe, ["CWE-20", "CWE-89"]);
  assert.equal(
    corroborated.canonicalFindings[0]?.id,
    baseOnly.canonicalFindings[0]?.id,
  );
  assert.equal(
    corroborated.canonicalFindings[0]?.fingerprint,
    baseOnly.canonicalFindings[0]?.fingerprint,
  );
  assert.equal(
    corroborated.sidecar.canonicalSources[0]?.identity.groupAnchor,
    baseOnly.sidecar.canonicalSources[0]?.identity.groupAnchor,
  );
});

test("canonical identity is stable when an overlapping corroborator starts earlier", () => {
  const precise = codeFinding({
    id: "later-start-precise",
    fingerprint: "fp-later-start-precise",
    evidence: "db.query(userSql)",
    location: { file: "src/db.js", startLine: 22, endLine: 22 },
  });
  const earlierRange = codeFinding({
    id: "earlier-start-range",
    fingerprint: "fp-earlier-start-range",
    evidence: "The traced range ends at db.query(userSql)",
    cwe: ["CWE-20", "CWE-89"],
    location: { file: "./src/db.js", startLine: 20, endLine: 22 },
  });
  const singleton = fuseFindings([
    scannerSource(precise, "scanner:later-start"),
  ]);
  const corroborated = fuseFindings([
    scannerSource(precise, "scanner:later-start"),
    scannerSource(earlierRange, "scanner:earlier-start"),
  ]);

  assert.equal(corroborated.canonicalFindings.length, 1);
  assert.equal(corroborated.canonicalFindings[0]?.evidence, earlierRange.evidence);
  assert.equal(
    corroborated.canonicalFindings[0]?.id,
    singleton.canonicalFindings[0]?.id,
  );
  assert.equal(
    corroborated.canonicalFindings[0]?.fingerprint,
    singleton.canonicalFindings[0]?.fingerprint,
  );
  assert.deepEqual(
    corroborated,
    fuseFindings([
      scannerSource(earlierRange, "scanner:earlier-start"),
      scannerSource(precise, "scanner:later-start"),
    ]),
  );
});

test("dependency fusion requires both package and advisory identity", () => {
  const npmLodash = dependencyFinding({
    id: "osv-lodash",
    fingerprint: "fp-osv-lodash",
    tool: "osv-scanner",
    identifiers: { cve: ["cve_2021_23337"] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.20" },
  });
  const npmLodashAgent = dependencyFinding({
    id: "agent-lodash",
    fingerprint: "fp-agent-lodash",
    tool: "hermsec-agent",
    identifiers: { cve: ["CVE-2021-23337"], ghsa: ["GHSA-35JH-R3H4-6JHM"] },
    cwe: ["CWE-79"],
    package: { ecosystem: "node", name: "LODASH", installedVersion: "4.17.20" },
  });
  const npmLodashOtherAdvisory = dependencyFinding({
    id: "osv-lodash-other",
    fingerprint: "fp-osv-lodash-other",
    identifiers: { cve: ["CVE-2020-8203"] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.20" },
  });
  const pypiLodash = dependencyFinding({
    id: "osv-pypi-lodash",
    fingerprint: "fp-osv-pypi-lodash",
    identifiers: { cve: ["CVE-2021-23337"] },
    package: { ecosystem: "pypi", name: "lodash", installedVersion: "1.0.0" },
  });
  const npmLodashDifferentVersion = dependencyFinding({
    id: "osv-lodash-old-version",
    fingerprint: "fp-osv-lodash-old-version",
    identifiers: { cve: ["CVE-2021-23337"] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.19" },
  });

  const result = fuseFindings([
    scannerSource(npmLodash, "scanner:lodash"),
    agentSource(npmLodashAgent, "agent:lodash"),
    scannerSource(npmLodashOtherAdvisory, "scanner:lodash-other"),
    scannerSource(pypiLodash, "scanner:pypi-lodash"),
    scannerSource(npmLodashDifferentVersion, "scanner:lodash-old-version"),
  ]);
  const scannerOnly = fuseFindings([
    scannerSource(npmLodash, "scanner:lodash"),
  ]);

  assert.equal(result.canonicalFindings.length, 4);
  assert.equal(result.sidecar.duplicateGroups.length, 1);
  assert.equal(result.sidecar.duplicateGroups[0]?.reason, "matching-package-advisory");
  const merged = result.canonicalFindings.find((finding) =>
    finding.identifiers?.cve?.includes("CVE-2021-23337") &&
    finding.package?.ecosystem === "npm" &&
    finding.package.installedVersion === "4.17.20"
  );
  assert.ok(merged);
  assert.deepEqual(merged.identifiers?.ghsa, ["GHSA-35JH-R3H4-6JHM"]);
  assert.equal(merged.id, scannerOnly.canonicalFindings[0]?.id);
});

test("dependency findings without advisory IDs remain isolated", () => {
  const scanner = dependencyFinding({
    id: "dependency-no-advisory-scanner",
    fingerprint: "fp-dependency-no-advisory-scanner",
    package: { ecosystem: "npm", name: "example", installedVersion: "1.2.3" },
  });
  const agent = dependencyFinding({
    id: "dependency-no-advisory-agent",
    fingerprint: "fp-dependency-no-advisory-agent",
    tool: "hermsec-agent",
    package: { ecosystem: "node", name: "EXAMPLE", installedVersion: "1.2.3" },
  });
  const otherVersion = dependencyFinding({
    id: "dependency-no-advisory-other-version",
    fingerprint: "fp-dependency-no-advisory-other-version",
    package: { ecosystem: "npm", name: "example", installedVersion: "2.0.0" },
  });
  delete scanner.identifiers;
  delete agent.identifiers;
  delete otherVersion.identifiers;

  const result = fuseFindings([
    scannerSource(scanner, "scanner:no-advisory"),
    agentSource(agent, "agent:no-advisory"),
    scannerSource(otherVersion, "scanner:other-version"),
  ]);

  assert.equal(result.canonicalFindings.length, 3);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
  assert.equal(
    new Set(result.canonicalFindings.map((finding) => finding.id)).size,
    3,
  );
});

test("incomplete or differently-advised dependency findings cannot merge", () => {
  const packageLessFirst = dependencyFinding({
    id: "package-less-first",
    fingerprint: "fp-package-less-first",
    identifiers: { cve: ["CVE-2026-1000"] },
  });
  const packageLessSecond = dependencyFinding({
    id: "package-less-second",
    fingerprint: "fp-package-less-second",
    identifiers: { cve: ["CVE-2026-2000"] },
  });
  delete packageLessFirst.package;
  delete packageLessSecond.package;
  const unknownVersionFirst = dependencyFinding({
    id: "unknown-version-first",
    fingerprint: "fp-unknown-version-first",
    identifiers: { cve: ["CVE-2026-3000"] },
    package: { ecosystem: "npm", name: "example" },
  });
  const unknownVersionSecond = dependencyFinding({
    id: "unknown-version-second",
    fingerprint: "fp-unknown-version-second",
    identifiers: { cve: ["CVE-2026-3000"] },
    package: { ecosystem: "node", name: "EXAMPLE" },
  });
  const differentCveFirst = dependencyFinding({
    id: "different-cve-first",
    fingerprint: "fp-different-cve-first",
    identifiers: { cve: ["CVE-2026-4000"] },
    package: { ecosystem: "npm", name: "example", installedVersion: "1.0.0" },
  });
  const differentCveSecond = dependencyFinding({
    id: "different-cve-second",
    fingerprint: "fp-different-cve-second",
    identifiers: { cve: ["CVE-2026-5000"] },
    package: { ecosystem: "node", name: "EXAMPLE", installedVersion: "1.0.0" },
  });

  const result = fuseFindings([
    scannerSource(packageLessFirst, "scanner:package-less-first"),
    agentSource(packageLessSecond, "agent:package-less-second"),
    scannerSource(unknownVersionFirst, "scanner:unknown-version-first"),
    agentSource(unknownVersionSecond, "agent:unknown-version-second"),
    scannerSource(differentCveFirst, "scanner:different-cve-first"),
    agentSource(differentCveSecond, "agent:different-cve-second"),
  ]);

  assert.equal(result.canonicalFindings.length, 6);
  assert.equal(result.sidecar.duplicateGroups.length, 0);
  assert.equal(
    new Set(result.canonicalFindings.map((finding) => finding.id)).size,
    6,
  );
});

test("fusion output is independent of input order", () => {
  const inputs: FindingFusionInput[] = [
    scannerSource(codeFinding({
      id: "scanner-near",
      fingerprint: "fp-scanner-near",
      location: { file: "src/query.js", startLine: 30, endLine: 31 },
    }), "scanner:near"),
    agentSource(codeFinding({
      id: "agent-near",
      fingerprint: "fp-agent-near",
      tool: "hermsec-agent",
      location: { file: "src/query.js", startLine: 32, endLine: 32 },
    }), "agent:near"),
    scannerSource(codeFinding({
      id: "scanner-far",
      fingerprint: "fp-scanner-far",
      location: { file: "src/query.js", startLine: 90, endLine: 90 },
    }), "scanner:far"),
  ];

  assert.deepEqual(
    fuseFindings(inputs),
    fuseFindings([...inputs].reverse()),
  );
});

test("fusion does not mutate nested raw finding inputs", () => {
  const scanner = codeFinding({
    id: "immutable-scanner",
    fingerprint: "fp-immutable-scanner",
    identifiers: { cve: ["CVE-2024-1000"] },
    location: { file: "src/app.js", startLine: 8, endLine: 8 },
    sourceLocations: [
      { file: "src/source.js", startLine: 3, endLine: 4 },
    ],
  });
  const agent = codeFinding({
    id: "immutable-agent",
    fingerprint: "fp-immutable-agent",
    tool: "hermsec-agent",
    identifiers: { cve: ["CVE-2024-1000"], ghsa: ["GHSA-AAAA-BBBB-CCCC"] },
    location: { file: "src/app.js", startLine: 7, endLine: 8 },
    sourceLocations: [
      { file: "src/request.js", startLine: 5, endLine: 6 },
    ],
    agent: {
      mode: "single-agent",
      source: "single-agent",
      provider: "test",
      generatedAt: "2026-07-25T00:00:00.000Z",
      candidateIds: ["candidate-1"],
      sourceFindingIds: ["source-1"],
    },
  });
  const inputs = [
    scannerSource(scanner, "scanner:immutable"),
    agentSource(agent, "agent:immutable"),
  ];
  const before = structuredClone(inputs);
  deepFreeze(inputs);

  const result = fuseFindings(inputs);

  assert.equal(result.canonicalFindings.length, 1);
  assert.deepEqual(inputs, before);
  assert.notEqual(result.canonicalFindings[0], scanner);
  assert.notEqual(result.canonicalFindings[0]?.identifiers, scanner.identifiers);
});

test("provenance contains immutable raw findings for every source", () => {
  const scanner = codeFinding({
    id: "provenance-scanner",
    fingerprint: "fp-provenance-scanner",
    evidence: "Semgrep matched db.query(req.query.id) at the sink.",
    location: { file: "src/app.js", startLine: 11, endLine: 11 },
    sourceLocations: [
      { file: "src/input.js", startLine: 2, endLine: 3 },
    ],
  });
  const agent = codeFinding({
    id: "provenance-agent",
    fingerprint: "fp-provenance-agent",
    tool: "hermsec-agent",
    evidence: "Agent traced db.query(req.query.id) at the sink.",
    location: { file: "src/app.js", startLine: 10, endLine: 11 },
    sourceLocations: [
      { file: "src/input.js", startLine: 2, endLine: 4 },
    ],
  });

  const result = fuseFindings([
    scannerSource(scanner, "scanner:provenance"),
    agentSource(agent, "agent:provenance"),
  ]);
  const sources = result.sidecar.canonicalSources[0]?.sources ?? [];

  assert.equal(sources.length, 2);
  assert.deepEqual(
    sources.map((source) => source.rawFinding.id).sort(),
    ["provenance-agent", "provenance-scanner"],
  );
  assert.equal(sources.every((source) => Object.isFrozen(source.rawFinding)), true);
  assert.equal(sources.every((source) => Object.isFrozen(source.identity)), true);
  assert.equal(sources.every((source) => source.contentDigest.startsWith("content-")), true);
  assert.equal(Object.isFrozen(result.sidecar), true);
  assert.equal(Object.isFrozen(result.sidecar.canonicalSources), true);
  assert.equal(Object.isFrozen(result.sidecar.duplicateGroups), true);
  assert.equal(Object.isFrozen(result.sidecar.canonicalSources[0]), true);
  assert.equal(Object.isFrozen(result.sidecar.canonicalSources[0]?.sources), true);
  assert.equal(Object.isFrozen(result.sidecar.canonicalSources[0]?.sourceIds), true);
  assert.equal(
    sources.every((source) => Object.isFrozen(source.rawFinding.sourceLocations)),
    true,
  );
  assert.equal(
    sources.every((source) => Object.isFrozen(source.rawFinding.sourceLocations?.[0])),
    true,
  );
  assert.equal(Object.isFrozen(scanner), false);
  assert.equal(Object.isFrozen(scanner.sourceLocations), false);
  assert.equal(Object.isFrozen(scanner.sourceLocations?.[0]), false);

  scanner.title = "Mutated after fusion";
  if (scanner.sourceLocations?.[0]) {
    scanner.sourceLocations[0].file = "src/mutated.js";
  }
  assert.equal(
    sources.find((source) => source.findingId === "provenance-scanner")?.rawFinding.title,
    "SQL injection at query sink",
  );
  assert.equal(
    sources.find((source) => source.findingId === "provenance-scanner")
      ?.rawFinding.sourceLocations?.[0]?.file,
    "src/input.js",
  );
  assert.throws(
    () => result.sidecar.canonicalSources.splice(0, 1),
    TypeError,
  );
  assert.throws(
    () => result.sidecar.canonicalSources[0]?.sources.splice(0, 1),
    TypeError,
  );
  assert.throws(
    () => sources[0]?.rawFinding.sourceLocations?.splice(0, 1),
    TypeError,
  );
});

test("fusion rejects inputs above its safe maximum before inspecting findings", () => {
  let propertyReads = 0;
  const poisonFinding = new Proxy({} as Finding, {
    get() {
      propertyReads += 1;
      throw new Error("finding should not be inspected");
    },
  });
  const inputs = Array.from(
    { length: MAX_FINDING_FUSION_INPUTS + 1 },
    (_, index): FindingFusionInput => ({
      finding: poisonFinding,
      sourceId: `oversized-${index}`,
    }),
  );

  assert.throws(
    () => fuseFindings(inputs),
    new RangeError(
      `Finding fusion accepts at most ${MAX_FINDING_FUSION_INPUTS} inputs; received ${inputs.length}.`,
    ),
  );
  assert.equal(propertyReads, 0);
});

function scannerSource(finding: Finding, sourceId: string): FindingFusionInput {
  return {
    finding,
    sourceId,
    sourceLabel: "Semgrep",
    sourceKind: "scanner",
  };
}

function agentSource(finding: Finding, sourceId: string): FindingFusionInput {
  return {
    finding,
    sourceId,
    sourceLabel: "Single agent",
    sourceKind: "agent",
  };
}

function codeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-sql",
    title: "SQL injection at query sink",
    category: "code",
    severity: "high",
    confidence: "high",
    description: "Request input reaches a dynamically constructed SQL query.",
    evidence: "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    remediation: "Use a parameterized query.",
    tool: "semgrep",
    ruleId: "javascript.sql-injection",
    cwe: ["CWE-89"],
    location: { file: "src/db.js", startLine: 10, endLine: 10 },
    fingerprint: "fp-sql",
    ...overrides,
  };
}

function dependencyFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-dependency",
    title: "Vulnerable dependency",
    category: "dependency",
    severity: "high",
    confidence: "confirmed",
    description: "The installed package version is affected by an advisory.",
    evidence: "package-lock.json records the affected version.",
    remediation: "Upgrade to a patched version.",
    tool: "osv-scanner",
    ruleId: "osv.dependency-advisory",
    identifiers: { cve: ["CVE-2021-23337"] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.20" },
    fingerprint: "fp-dependency",
    ...overrides,
  };
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}
