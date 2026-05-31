import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../shared/types.js";
import { evaluateFindingsSimple, type SimpleEvalMetrics, type SimpleGroundTruthFinding } from "./metrics.js";

export async function runEvaluation(options: {
  expectedPath: string;
  findingsPath: string;
  out?: string;
}): Promise<SimpleEvalMetrics> {
  const expected = JSON.parse(await fs.readFile(options.expectedPath, "utf8")) as SimpleGroundTruthFinding[];
  const actual = JSON.parse(await fs.readFile(options.findingsPath, "utf8")) as { findings?: Finding[] } | Finding[];
  const findings = Array.isArray(actual) ? actual : actual.findings ?? [];
  const metrics = evaluateFindingsSimple(expected, findings);
  if (options.out) {
    await fs.mkdir(path.dirname(options.out), { recursive: true });
    await fs.writeFile(options.out, `${JSON.stringify(metrics, null, 2)}\n`, "utf8");
  }
  return metrics;
}

export function compareEvaluations(scannerOnly: SimpleEvalMetrics, agentAssisted: SimpleEvalMetrics): {
  deltaPrecision: number;
  deltaRecall: number;
  deltaF1: number;
  scannerOnly: SimpleEvalMetrics;
  agentAssisted: SimpleEvalMetrics;
} {
  return {
    deltaPrecision: agentAssisted.precision - scannerOnly.precision,
    deltaRecall: agentAssisted.recall - scannerOnly.recall,
    deltaF1: agentAssisted.f1 - scannerOnly.f1,
    scannerOnly,
    agentAssisted,
  };
}
