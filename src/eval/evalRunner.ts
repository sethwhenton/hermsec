import fs from "node:fs/promises";
import path from "node:path";
import { runScan } from "../core/scan.js";
import type { CommandResult } from "../shared/types.js";
import { evaluateFindingsSimple, type SimpleGroundTruthFinding } from "./metrics.js";
import { loadEvaluationFixture } from "./suite.js";

export {
  loadEvaluationFixture,
  runScoredEvaluationSuite,
} from "./suite.js";
export type {
  EvaluationSuiteInput,
  ScoredEvaluationBundle,
} from "./suite.js";

export async function runEvaluation(options: {
  cwd: string;
  suite?: string;
  mode?: "scanner-only" | "agent-assisted";
  outputDirectory?: string;
}): Promise<CommandResult> {
  const suite = path.resolve(options.cwd, options.suite ?? "tests/fixtures/repos/node-express-vulnerable");
  const expectedPath = path.join(suite, "groundtruth.json");
  const expected = JSON.parse(await fs.readFile(expectedPath, "utf8")) as SimpleGroundTruthFinding[];
  const fixture = await loadEvaluationFixture(suite);
  const scan = await runScan({ target: fixture.projectRoot, mode: "offline" });
  const metrics = evaluateFindingsSimple(expected, scan.findings);
  const outDir = path.resolve(options.cwd, options.outputDirectory ?? ".hermsec/evaluation");
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(outDir, `${path.basename(suite)}-${options.mode ?? "scanner-only"}-summary.json`);
  await fs.writeFile(outPath, `${JSON.stringify({ metrics, scanId: scan.id, suite, mode: options.mode ?? "scanner-only" }, null, 2)}\n`, "utf8");
  return {
    ok: true,
    message: `Evaluation completed: precision ${metrics.precision.toFixed(2)}, recall ${metrics.recall.toFixed(2)}, F1 ${metrics.f1.toFixed(2)}.`,
    data: { metrics, outputPath: outPath },
  };
}
