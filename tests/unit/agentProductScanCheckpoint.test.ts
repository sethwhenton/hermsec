import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildProductAgentResumeMetadata,
  createProductAgentCheckpointStore,
  createProductAgentScanCheckpoint,
  productAgentTargetHash,
  resolveProductAgentCheckpointLocation,
  upsertProductAgentCheckpointCandidate,
  upsertProductAgentCheckpointTask,
} from "../../src/agent/productScanCheckpoint.js";
import {
  buildProductAgentProgressEvent,
  emitProductAgentProgress,
} from "../../src/agent/productScanProgress.js";
import type { ProductAgentScanMode } from "../../src/agent/productScan.js";
import type { ScanProgressEvent } from "../../src/shared/types.js";

const fixedNow = () => new Date("2026-06-28T10:00:00.000Z");

test("product agent checkpoint store writes under report output .checkpoints by target hash and assist mode", async () => {
  const reportRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-checkpoint-report-"));
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-checkpoint-repo-"));
  const store = createProductAgentCheckpointStore({
    reportOutputDirectory: reportRoot,
    target: repoRoot,
    assistMode: "moa-assisted",
    now: fixedNow,
  });

  assert.equal(store.location.checkpointDir, path.join(reportRoot, ".checkpoints"));
  assert.match(store.location.fileName, /^[a-f0-9]{16}-moa-assisted\.json$/u);
  assert.equal(store.location.targetHash, productAgentTargetHash(repoRoot));

  let checkpoint = createProductAgentScanCheckpoint({
    reportOutputDirectory: reportRoot,
    target: repoRoot,
    assistMode: "moa-assisted",
    now: fixedNow,
    currentPhase: "candidate",
  });
  checkpoint = upsertProductAgentCheckpointTask(checkpoint, {
    id: "injection-and-execution",
    label: "Injection and execution specialist",
    phase: "task",
    status: "completed",
    candidateIds: ["cand-1"],
  }, fixedNow);
  checkpoint = upsertProductAgentCheckpointCandidate(checkpoint, {
    id: "cand-1",
    source: "moa-specialist",
    status: "accepted",
    title: "Unsafe eval on request input",
    findingId: "finding-1",
  }, fixedNow);
  checkpoint = {
    ...checkpoint,
    currentPhase: "checkpoint",
    finalFindingIds: ["finding-1"],
  };

  const written = await store.write(checkpoint);
  assert.equal(written.location.checkpointPath, store.location.checkpointPath);
  assert.equal(written.resume.available, true);
  assert.deepEqual(written.resume.completedTaskIds, ["injection-and-execution"]);
  assert.equal(written.resume.candidateCount, 1);
  assert.equal(written.resume.acceptedCandidateCount, 1);
  assert.equal(written.resume.finalFindingCount, 1);

  const raw = await fs.readFile(store.location.checkpointPath, "utf8");
  assert.match(raw, /"kind": "product-agent-scan"/u);

  const read = await store.read();
  assert.equal(read.resume.available, true);
  assert.equal(read.resume.lastPhase, "checkpoint");
  assert.equal(read.resume.resumedAt, "2026-06-28T10:00:00.000Z");
  assert.equal(read.checkpoint?.candidates[0]?.id, "cand-1");

  await store.clear();
  await fs.rm(reportRoot, { recursive: true, force: true });
  await fs.rm(repoRoot, { recursive: true, force: true });
});

test("product agent checkpoint resume metadata reports missing and invalid checkpoints safely", async () => {
  const reportRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-checkpoint-invalid-"));
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-checkpoint-invalid-repo-"));
  const store = createProductAgentCheckpointStore({
    reportOutputDirectory: reportRoot,
    target: repoRoot,
    assistMode: "scanner-moa-assisted",
    now: fixedNow,
  });

  const missing = await store.read();
  assert.equal(missing.resume.available, false);
  assert.equal(missing.resume.reason, "missing");

  await fs.mkdir(store.location.checkpointDir, { recursive: true });
  await fs.writeFile(store.location.checkpointPath, "{not-json", "utf8");

  const invalid = await store.read();
  assert.equal(invalid.resume.available, false);
  assert.equal(invalid.resume.reason, "invalid-json");

  await fs.rm(reportRoot, { recursive: true, force: true });
  await fs.rm(repoRoot, { recursive: true, force: true });
});

test("product agent checkpoint helpers reject non-product assist modes", () => {
  assert.throws(
    () => resolveProductAgentCheckpointLocation({
      reportOutputDirectory: os.tmpdir(),
      target: process.cwd(),
      assistMode: "deep-assisted" as ProductAgentScanMode,
    }),
    /only support product agent assist modes/u,
  );
});

test("product agent progress helpers describe candidate, task, revalidation, and checkpoint phases", () => {
  const phases = ["candidate", "task", "revalidation", "checkpoint"] as const;
  for (const phase of phases) {
    const event = buildProductAgentProgressEvent({
      phase,
      assistMode: "moa-assisted",
      status: "running",
    });
    assert.equal(event.stage, phase);
    assert.equal(event.details?.some((detail) => detail.id === "phase"), true);
  }

  const candidateEvent = buildProductAgentProgressEvent({
    phase: "candidate",
    assistMode: "moa-assisted",
    status: "running",
    taskId: "injection-and-execution",
    taskLabel: "Injection specialist",
    roleId: "injection-and-execution",
    candidateCount: 3,
    totalCandidates: 5,
    acceptedCount: 1,
    rejectedCount: 1,
    needsReviewCount: 1,
  });
  assert.equal(detailValue(candidateEvent.details, "candidate-count"), "3/5");
  assert.equal(detailValue(candidateEvent.details, "accepted-count"), "1");
  assert.equal(detailValue(candidateEvent.details, "rejected-count"), "1");
  assert.equal(detailValue(candidateEvent.details, "needs-review-count"), "1");

  const location = resolveProductAgentCheckpointLocation({
    reportOutputDirectory: os.tmpdir(),
    target: process.cwd(),
    assistMode: "moa-assisted",
  });
  const checkpoint = createProductAgentScanCheckpoint({
    reportOutputDirectory: os.tmpdir(),
    target: process.cwd(),
    assistMode: "moa-assisted",
    now: fixedNow,
    currentPhase: "revalidation",
    candidates: [
      {
        id: "cand-1",
        source: "moa-specialist",
        status: "needs-review",
        updatedAt: "2026-06-28T10:00:00.000Z",
      },
    ],
  });
  const resume = buildProductAgentResumeMetadata(checkpoint, location, fixedNow);
  const checkpointEvent = buildProductAgentProgressEvent({
    phase: "checkpoint",
    assistMode: "moa-assisted",
    status: "completed",
    checkpointPath: location.checkpointPath,
    resume,
  });
  assert.equal(detailValue(checkpointEvent.details, "checkpoint-path"), location.checkpointPath);
  assert.equal(detailValue(checkpointEvent.details, "resume"), "available");
  assert.equal(detailValue(checkpointEvent.details, "resume-candidates"), "1");
  assert.equal(detailValue(checkpointEvent.details, "resume-last-phase"), "Candidate revalidation");
});

test("product agent progress emit helper stamps schema version and timestamp", () => {
  const events: ScanProgressEvent[] = [];
  emitProductAgentProgress((event) => events.push(event), {
    phase: "revalidation",
    assistMode: "scanner-moa-assisted",
    status: "completed",
    candidateCount: 2,
  });

  assert.equal(events.length, 1);
  assert.equal(events[0]?.schemaVersion, "1.0");
  assert.equal(events[0]?.stage, "revalidation");
  assert.match(events[0]?.timestamp ?? "", /^\d{4}-\d{2}-\d{2}T/u);
});

function detailValue(details: readonly { id?: string; value?: string }[] | undefined, id: string): string | undefined {
  return details?.find((detail) => detail.id === id)?.value;
}
