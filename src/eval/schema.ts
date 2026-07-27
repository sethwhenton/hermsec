import type { FindingCategory, Severity } from "../shared/types.js";

export type EvalFindingCategory = FindingCategory;
export type EvalSeverity = Severity;
export type EvalVulnerabilityClass = string;

export type EvalIdentifiers = {
  cve: string[];
  ghsa: string[];
  osv: string[];
};

export type EvalLocation = {
  path: string;
  startLine?: number;
  endLine?: number;
};

export type GroundTruthEvidenceType =
  | "primary-location"
  | "source-and-sink"
  | "secret-location"
  | "package-advisory";

export type GroundTruthEvidence = {
  type: GroundTruthEvidenceType;
  sourceLocations?: EvalLocation[];
  description?: string;
};

export type EvalPackageRef = {
  ecosystem: string;
  name: string;
  installedVersion?: string;
};

export type SeverityToleranceMode = "exact" | "one-step" | "category-only";
export type CweToleranceMode = "exact" | "alias" | "weakness-family";

export type GroundTruthMatchHints = {
  lineTolerance?: number;
  severityTolerance?: SeverityToleranceMode;
  cweTolerance?: CweToleranceMode;
  advisoryMatchOptional?: boolean;
};

export type GroundTruthMatchPolicy = {
  category: "exact";
  vulnerabilityClass: "exact" | "compatible";
  location: "required" | "optional";
  line: "required" | "optional";
  evidence: GroundTruthEvidenceType;
};

export type GroundTruthFinding = {
  id: string;
  category: EvalFindingCategory;
  vulnerabilityClass?: EvalVulnerabilityClass;
  title: string;
  severity: EvalSeverity;
  cwe: string[];
  identifiers: EvalIdentifiers;
  location?: EvalLocation;
  evidence?: GroundTruthEvidence;
  matchPolicy?: GroundTruthMatchPolicy;
  package?: EvalPackageRef;
  ruleIds?: string[];
  aliases?: string[];
  tags?: string[];
  matchHints?: GroundTruthMatchHints;
};

export type ActualFindingProjection = {
  id: string;
  fingerprint: string;
  category: EvalFindingCategory;
  vulnerabilityClass?: EvalVulnerabilityClass;
  title: string;
  severity: EvalSeverity;
  cwe: string[];
  identifiers: EvalIdentifiers;
  ruleIds: string[];
  location?: EvalLocation;
  sourceLocations?: EvalLocation[];
  package?: EvalPackageRef;
  tool?: string;
  disposition?: "accepted" | "rejected" | "needs-review";
};

export type IgnoredActualFinding = {
  id: string;
  fingerprint: string;
  category: EvalFindingCategory;
  reason: "duplicate";
  duplicateOfId: string;
  duplicateOfFingerprint: string;
  noiseKey: string;
};

export type MatchThresholds = {
  minMatchScore: number;
  defaultLineTolerance: number;
  severityTolerance: SeverityToleranceMode;
  cweTolerance: CweToleranceMode;
};

export const DEFAULT_MATCH_THRESHOLDS: MatchThresholds = {
  minMatchScore: 60,
  defaultLineTolerance: 3,
  severityTolerance: "one-step",
  cweTolerance: "weakness-family",
};

export type CandidateSignal = {
  name: string;
  points: number;
  explanation: string;
};

export type MatchCandidate = {
  expectedId: string;
  actualId: string;
  actualFingerprint: string;
  expectedCategory: EvalFindingCategory;
  actualCategory: EvalFindingCategory;
  expectedVulnerabilityClass?: EvalVulnerabilityClass;
  actualVulnerabilityClass?: EvalVulnerabilityClass;
  actualDisposition?: "accepted" | "rejected" | "needs-review";
  expectedPath?: string;
  actualPath?: string;
  score: number;
  evidenceScore: number;
  eligible: boolean;
  rejectionReasons: string[];
  signals: CandidateSignal[];
};

export type AcceptedMatch = MatchCandidate & {
  accepted: true;
};

export type MatchResult = {
  matches: AcceptedMatch[];
  rejectedCandidates: MatchCandidate[];
  falsePositives: ActualFindingProjection[];
  falseNegatives: GroundTruthFinding[];
  ignoredActual: IgnoredActualFinding[];
  trueNegative: boolean;
  thresholds: MatchThresholds;
};

export type DetectionCounts = {
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegative: number;
};

export type WilsonInterval = {
  lower: number;
  upper: number;
  confidence: number;
};

export type EvalMetrics = {
  totalExpected: number;
  totalActual: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegativeCases: number;
  precision: number;
  precisionDefined: boolean;
  precisionInterval: WilsonInterval | null;
  recall: number;
  recallDefined: boolean;
  recallInterval: WilsonInterval | null;
  f1: number;
  f1Defined: boolean;
  falsePositiveRate: number;
  falsePositiveRateDefined: boolean;
  falseNegativeRate: number;
  macroF1: number;
  weightedF1: number;
  groupMetricsDefined: boolean;
  macroF1IncludingSpurious: number;
  weightedF1IncludingSpurious: number;
  predictionOnlyGroupCount: number;
  categorySupport: number;
  supportedCategoryCount: number;
  duplicateCount: number;
  duplicateRate: number;
  cleanCaseCount: number;
  cleanTrueNegativeCases: number;
  cleanFalsePositiveCases: number;
  cleanSpecificity: number;
  cleanSpecificityDefined: boolean;
  cleanSpecificityInterval: WilsonInterval | null;
  falseFindingsPerKloc: number | null;
};

export type TruthSetV2 = {
  schemaVersion: "2.0";
  fixtureId: string;
  findings: GroundTruthFinding[];
};

export type FixtureVariant = "vulnerable" | "clean";

export type FixtureManifestV2 = {
  schemaVersion: "2.0";
  id: string;
  pairId: string;
  variant: FixtureVariant;
  language: string;
  projectRoot: "project";
  evaluatorFiles: string[];
  entrypoints: string[];
  sourceFiles: string[];
  supportedVulnerabilityClasses: string[];
  expectedFindingCount: number;
  pairedFixtureId: string;
  safety: {
    networkRequired: false;
    executionRequired: false;
    containsRealSecrets: false;
    executionPolicy: "never";
    networkPolicy: "deny";
  };
};

export type GroupedMetricSummary = {
  supportedMacroF1: number;
  supportedWeightedF1: number;
  supportedGroupCount: number;
  truthSupport: number;
  observedMacroF1: number;
  observedWeightedF1: number;
  observedGroupCount: number;
  observedWeight: number;
  predictionOnlyGroupCount: number;
};

export type SelectiveEvaluationCounts = {
  totalExpected: number;
  acceptedTruePositive: number;
  acceptedFalsePositive: number;
  needsReviewTruePositive: number;
  needsReviewFalsePositive: number;
  rejectedTruePositive?: number;
  rejectedFalsePositive?: number;
};

export type SelectiveMetrics = {
  totalPredictions: number;
  abstainedPredictions: number;
  abstentionRate: number;
  abstentionRateDefined: boolean;
  selectivePrecision: number;
  selectivePrecisionDefined: boolean;
  selectivePrecisionInterval: WilsonInterval | null;
  acceptedCoverage: number;
  acceptedCoverageDefined: boolean;
  needsReviewRecall: number;
  needsReviewRecallDefined: boolean;
};

export type ExecutionCompletenessInput = {
  plannedComponents: string[];
  completedComponents: string[];
  failedComponents?: string[];
  skippedComponents?: string[];
  eligibleFiles?: number;
  inspectedFiles?: number;
  inspectedBytes?: number;
  unsupportedLanguages?: string[];
  degradedReasons?: string[];
};

export type ExecutionCompleteness = {
  status: "complete" | "partial" | "degraded";
  plannedComponentCount: number;
  completedComponentCount: number;
  failedComponents: string[];
  skippedComponents: string[];
  componentCompletionRate: number;
  eligibleFiles: number | null;
  inspectedFiles: number | null;
  fileCoverage: number | null;
  inspectedBytes: number;
  unsupportedLanguages: string[];
  degradedReasons: string[];
};
