import fs from "node:fs/promises";
import path from "node:path";
import type { CommandResult } from "../shared/types.js";
import type { SimpleEvalMetrics } from "./metrics.js";

export async function compareEvaluations(options: {
  cwd: string;
  scannerOnly: string;
  agentAssisted: string;
  outputPath?: string;
}): Promise<CommandResult> {
  const scannerOnly = await readMetrics(options.scannerOnly);
  const agentAssisted = await readMetrics(options.agentAssisted);
  const comparison = {
    deltaPrecision: agentAssisted.precision - scannerOnly.precision,
    deltaRecall: agentAssisted.recall - scannerOnly.recall,
    deltaF1: agentAssisted.f1 - scannerOnly.f1,
    scannerOnly,
    agentAssisted,
  };
  if (options.outputPath) {
    const out = path.resolve(options.cwd, options.outputPath);
    await fs.mkdir(path.dirname(out), { recursive: true });
    await fs.writeFile(out, `${JSON.stringify(comparison, null, 2)}\n`, "utf8");
  }
  return {
    ok: true,
    message: `Evaluation comparison completed. Delta F1: ${comparison.deltaF1.toFixed(2)}.`,
    data: comparison,
  };
}

async function readMetrics(file: string): Promise<SimpleEvalMetrics> {
  const parsed = JSON.parse(await fs.readFile(file, "utf8")) as { metrics?: SimpleEvalMetrics } | SimpleEvalMetrics;
  if (isWrappedMetrics(parsed)) {
    return parsed.metrics;
  }
  return parsed as SimpleEvalMetrics;
}

function isWrappedMetrics(value: { metrics?: SimpleEvalMetrics } | SimpleEvalMetrics): value is { metrics: SimpleEvalMetrics } {
  return "metrics" in value && value.metrics !== undefined;
}
