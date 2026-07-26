import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../shared/types.js";
import { parseGroundTruthDocument } from "./groundTruthSchema.js";
import { evaluateFindings, type EvalMetrics } from "./metrics.js";

export {
  loadEvaluationFixture,
  runScoredEvaluationSuite,
} from "./suite.js";
export type {
  EvaluationSuiteCaseInput,
  EvaluationSuiteInput,
  EvaluationSuiteRunInput,
  LoadedEvaluationFixture,
  ScoredEvaluationBundle,
  ScoredEvaluationCase,
  ScoredEvaluationRun,
} from "./suite.js";

export async function runEvaluation(options: {
  expectedPath: string;
  findingsPath: string;
  out?: string;
}): Promise<EvalMetrics> {
  const expectedDocument = JSON.parse(
    await fs.readFile(options.expectedPath, "utf8"),
  ) as unknown;
  const expected = parseGroundTruthDocument(
    expectedDocument,
    path.dirname(options.expectedPath),
  );
  const actual = JSON.parse(await fs.readFile(options.findingsPath, "utf8")) as { findings?: Finding[] } | Finding[];
  const findings = Array.isArray(actual) ? actual : actual.findings ?? [];
  const metrics = evaluateFindings(expected, findings, {
    fixtureRoot: path.dirname(options.expectedPath),
  });
  if (options.out) {
    await fs.mkdir(path.dirname(options.out), { recursive: true });
    await fs.writeFile(options.out, `${JSON.stringify(metrics, null, 2)}\n`, "utf8");
  }
  return metrics;
}

export function compareEvaluations<T extends {
  precision: number;
  recall: number;
  f1: number;
}>(scannerOnly: T, agentAssisted: T): {
  deltaPrecision: number;
  deltaRecall: number;
  deltaF1: number;
  scannerOnly: T;
  agentAssisted: T;
} {
  return {
    deltaPrecision: agentAssisted.precision - scannerOnly.precision,
    deltaRecall: agentAssisted.recall - scannerOnly.recall,
    deltaF1: agentAssisted.f1 - scannerOnly.f1,
    scannerOnly,
    agentAssisted,
  };
}
