import type { FindingCategory, Severity } from "../shared/types.js";

export type EvalFindingCategory = FindingCategory;
export type EvalSeverity = Severity;

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

export type GroundTruthFinding = {
  id: string;
  category: EvalFindingCategory;
  title: string;
  severity: EvalSeverity;
  cwe: string[];
  identifiers: EvalIdentifiers;
  location?: EvalLocation;
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
  title: string;
  severity: EvalSeverity;
  cwe: string[];
  identifiers: EvalIdentifiers;
  ruleIds: string[];
  location?: EvalLocation;
  package?: EvalPackageRef;
  tool?: string;
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
  expectedPath?: string;
  actualPath?: string;
  score: number;
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

export type EvalMetrics = {
  totalExpected: number;
  totalActual: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegativeCases: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  macroF1: number;
  weightedF1: number;
};
