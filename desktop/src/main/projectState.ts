import { createHash } from "node:crypto";
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

export interface ProjectStateFingerprint {
  kind: "git" | "filesystem";
  fingerprint: string;
  gitHead?: string;
  gitBranch?: string;
  gitDirty?: boolean;
  gitStatusHash?: string;
  fileStateHash?: string;
  capturedAt: string;
}

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hermsec",
  "node_modules",
  "dist",
  "out",
  "build",
  "coverage",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
]);

export function getProjectStateFingerprint(projectPath: string): ProjectStateFingerprint {
  const normalized = path.resolve(projectPath);
  const git = gitState(normalized);
  const capturedAt = new Date().toISOString();
  if (git) {
    const fingerprint = hashParts(["git", normalized, git.head, git.branch, String(git.dirty), git.statusHash]);
    return {
      kind: "git",
      fingerprint,
      gitHead: git.head,
      gitBranch: git.branch,
      gitDirty: git.dirty,
      gitStatusHash: git.statusHash,
      capturedAt,
    };
  }

  const fileStateHash = fileTreeHash(normalized);
  return {
    kind: "filesystem",
    fingerprint: hashParts(["filesystem", normalized, fileStateHash]),
    fileStateHash,
    capturedAt,
  };
}

export function projectStateChanged(
  previous: ProjectStateFingerprint | undefined,
  current: ProjectStateFingerprint,
): boolean {
  return !previous || previous.fingerprint !== current.fingerprint;
}

function gitState(cwd: string): { head: string; branch: string; dirty: boolean; statusHash: string } | undefined {
  const inside = runGit(cwd, ["rev-parse", "--is-inside-work-tree"]);
  if (inside.status !== 0 || inside.stdout.trim() !== "true") {
    return undefined;
  }

  const head = runGit(cwd, ["rev-parse", "HEAD"]).stdout.trim() || "unknown";
  const branch = runGit(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout.trim() || "unknown";
  const status = runGit(cwd, ["status", "--porcelain=v1"]).stdout.replace(/\r\n/g, "\n");
  return {
    head,
    branch,
    dirty: status.trim().length > 0,
    statusHash: hashParts([status]),
  };
}

function runGit(cwd: string, args: string[]): { status: number; stdout: string } {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
  };
}

function fileTreeHash(root: string): string {
  const parts: string[] = [];
  walk(root, root, parts);
  return hashParts(parts.sort());
}

function walk(root: string, current: string, parts: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(current);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (IGNORED_DIRECTORIES.has(entry)) continue;
    const absolutePath = path.join(current, entry);
    let stat;
    try {
      stat = statSync(absolutePath);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      walk(root, absolutePath, parts);
      continue;
    }
    if (!stat.isFile()) continue;
    const relative = path.relative(root, absolutePath).replace(/\\/g, "/");
    parts.push(`${relative}:${stat.size}:${Math.floor(stat.mtimeMs)}`);
  }
}

function hashParts(parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(part);
    hash.update("\0");
  }
  return hash.digest("hex");
}
