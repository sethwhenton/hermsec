import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { redactForReport } from "../agent/redaction.js";
import type { Finding } from "../shared/types.js";
import { stableId } from "../shared/text.js";
import type { EvidenceArtifact, EvidenceBundle, EvidenceReference } from "./schema.js";

export type RawEvidenceInput = {
  scanner: string;
  fileName?: string;
  content?: string | Buffer | object;
  status?: "stored" | "missing";
  findingIds?: string[];
};

export async function storeEvidenceBundle(input: {
  scanId: string;
  findings: readonly Finding[];
  rawDir: string;
  rawEvidence?: readonly RawEvidenceInput[];
}): Promise<EvidenceBundle> {
  await fs.mkdir(input.rawDir, { recursive: true });
  const artifacts: EvidenceArtifact[] = [];
  let redactionApplied = false;

  for (const artifact of input.rawEvidence ?? []) {
    if (artifact.status === "missing" || artifact.content === undefined) {
      artifacts.push({
        scanner: artifact.scanner,
        path: artifact.fileName ?? `${safeArtifactName(artifact.scanner)}.json`,
        sha256: "",
        sizeBytes: 0,
        status: "missing"
      });
      continue;
    }

    const rendered = renderRawContent(artifact.content);
    const redacted = redactForReport(rendered);
    redactionApplied ||= redacted.redacted;
    const fileName = safeArtifactName(artifact.fileName ?? `${artifact.scanner}.json`);
    const destination = path.join(input.rawDir, fileName);
    await fs.writeFile(destination, redacted.value, "utf8");
    const bytes = Buffer.byteLength(redacted.value, "utf8");
    artifacts.push({
      scanner: artifact.scanner,
      path: path.join("raw", fileName).replace(/\\/g, "/"),
      sha256: sha256(redacted.value),
      sizeBytes: bytes,
      status: redacted.redacted ? "redacted" : "stored"
    });
  }

  const findingEvidence = buildFindingEvidence(input.findings, artifacts);
  return {
    bundleId: stableId(`${input.scanId}:${artifacts.map((artifact) => artifact.sha256).join(":")}`, "evidence"),
    redactionApplied,
    rawArtifacts: artifacts.sort((left, right) => left.scanner.localeCompare(right.scanner)),
    findingEvidence
  };
}

export function buildFindingEvidence(
  findings: readonly Finding[],
  artifacts: readonly EvidenceArtifact[] = []
): Record<string, EvidenceReference[]> {
  const artifactByScanner = new Map<string, EvidenceArtifact>();
  for (const artifact of artifacts) {
    artifactByScanner.set(artifact.scanner, artifact);
  }

  const result: Record<string, EvidenceReference[]> = {};
  for (const finding of findings) {
    const artifact = artifactByScanner.get(finding.tool);
    const location = finding.location
      ? {
          file: finding.location.file,
          ...(finding.location.startLine !== undefined ? { startLine: finding.location.startLine } : {}),
          ...(finding.location.endLine !== undefined ? { endLine: finding.location.endLine } : {})
        }
      : undefined;

    result[finding.id] = [
      {
        scanner: finding.tool,
        ...(artifact ? { artifactPath: artifact.path } : {}),
        ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
        message: finding.evidence,
        ...(location ? { location } : {})
      }
    ];
  }
  return result;
}

function renderRawContent(content: string | Buffer | object): string {
  if (Buffer.isBuffer(content)) {
    return content.toString("utf8");
  }
  if (typeof content === "string") {
    return content;
  }
  return JSON.stringify(content, null, 2);
}

function safeArtifactName(value: string): string {
  const base = path.basename(value).replace(/[^\w.\-]+/g, "-");
  return base.length > 0 ? base : "artifact.json";
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}
