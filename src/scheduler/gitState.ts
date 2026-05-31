import crypto from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { BaselineRecord, GitChangeDetection, GitFileChange, GitState } from "./types.js";

const execFileAsync = promisify(execFile);
const maxHashBytes = 1024 * 1024;

async function git(cwd: string, args: string[]): Promise<string> {
  const result = await execFileAsync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 4,
    timeout: 10000,
    windowsHide: true,
  });
  return String(result.stdout).trim();
}

async function gitMaybe(cwd: string, args: string[]): Promise<string | undefined> {
  try {
    return await git(cwd, args);
  } catch {
    return undefined;
  }
}

function statusFromCode(code: string): GitFileChange["status"] {
  const marker = code.trim();
  if (marker === "??") {
    return "untracked";
  }
  if (marker.includes("D")) {
    return "deleted";
  }
  if (marker.includes("R")) {
    return "renamed";
  }
  if (marker.includes("C")) {
    return "copied";
  }
  if (marker.includes("A")) {
    return "added";
  }
  if (marker.includes("M")) {
    return "modified";
  }
  return "unknown";
}

export function parsePorcelainStatus(raw: string): GitFileChange[] {
  if (!raw) {
    return [];
  }
  const parts = raw.split("\0").filter(Boolean);
  const changes: GitFileChange[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    const entry = parts[index] ?? "";
    const code = entry.slice(0, 2);
    const filePath = entry.slice(3);
    const status = statusFromCode(code);
    const maybeOldPath = parts[index + 1];
    if ((status === "renamed" || status === "copied") && maybeOldPath) {
      const oldPath = maybeOldPath;
      index += 1;
      changes.push({ path: filePath, oldPath, status });
    } else {
      changes.push({ path: filePath, status });
    }
  }
  return changes;
}

function parseNameStatus(raw: string): GitFileChange[] {
  if (!raw) {
    return [];
  }
  return raw
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const columns = line.split("\t");
      const code = columns[0] ?? "";
      const status = statusFromCode(code);
      const newPath = columns[2];
      if ((status === "renamed" || status === "copied") && newPath) {
        return { status, oldPath: columns[1] ?? "", path: newPath };
      }
      return { status, path: columns[1] ?? "" };
    })
    .filter((change) => change.path.length > 0);
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isLikelyTextPath(filePath: string): boolean {
  const extension = path.extname(filePath).toLowerCase();
  return [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    ".py",
    ".go",
    ".rs",
    ".java",
    ".cs",
    ".rb",
    ".php",
    ".html",
    ".css",
  ].includes(extension);
}

async function fileFingerprint(repoRoot: string, relativePath: string): Promise<string> {
  const absolutePath = path.resolve(repoRoot, relativePath);
  if (!isInside(repoRoot, absolutePath)) {
    return `${relativePath}:outside-repo`;
  }

  try {
    const stat = await fs.stat(absolutePath);
    if (!stat.isFile()) {
      return `${relativePath}:not-file:${stat.size}:${stat.mtimeMs}`;
    }
    if (stat.size > maxHashBytes || !isLikelyTextPath(relativePath)) {
      return `${relativePath}:meta:${stat.size}:${Math.trunc(stat.mtimeMs)}`;
    }
    const content = await fs.readFile(absolutePath);
    const digest = crypto.createHash("sha256").update(content).digest("hex");
    return `${relativePath}:sha256:${digest}`;
  } catch {
    return `${relativePath}:missing`;
  }
}

async function buildWorkingTreeFingerprint(
  repoRoot: string,
  headCommit: string | undefined,
  statusEntries: GitFileChange[],
): Promise<string> {
  const hash = crypto.createHash("sha256");
  hash.update(headCommit ?? "NO_HEAD");
  const paths = [...new Set(statusEntries.flatMap((entry) => [entry.path, entry.oldPath].filter(Boolean) as string[]))]
    .sort();
  hash.update(JSON.stringify(statusEntries.slice().sort((a, b) => a.path.localeCompare(b.path))));
  for (const filePath of paths) {
    hash.update(await fileFingerprint(repoRoot, filePath));
  }
  return hash.digest("hex");
}

export async function readGitState(targetPath: string): Promise<GitState> {
  const repoRoot = await git(targetPath, ["rev-parse", "--show-toplevel"]);
  const gitDir = await git(targetPath, ["rev-parse", "--git-dir"]);
  const branch = await gitMaybe(targetPath, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const headCommit = await gitMaybe(targetPath, ["rev-parse", "--verify", "HEAD"]);
  const statusRaw = await git(targetPath, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  const statusEntries = parsePorcelainStatus(statusRaw);
  const workingTreeFingerprint = await buildWorkingTreeFingerprint(repoRoot, headCommit, statusEntries);

  return {
    kind: "git",
    repoRoot,
    gitDir,
    ...(branch ? { branch } : {}),
    ...(headCommit ? { headCommit } : {}),
    hasCommits: Boolean(headCommit),
    statusEntries,
    workingTreeFingerprint,
  };
}

async function diffFromBaseline(targetPath: string, baseline: BaselineRecord, state: GitState): Promise<GitFileChange[]> {
  if (!baseline.headCommit || !state.headCommit || baseline.headCommit === state.headCommit) {
    return [];
  }
  const raw = await gitMaybe(targetPath, [
    "diff",
    "--name-status",
    "-M",
    "-C",
    baseline.headCommit,
    state.headCommit,
  ]);
  return raw ? parseNameStatus(raw) : [];
}

export async function detectGitChanges(
  targetPath: string,
  baseline?: BaselineRecord,
): Promise<GitChangeDetection> {
  let state: GitState;
  try {
    state = await readGitState(targetPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const notGit = /not a git repository|not a git repo|fatal/i.test(message);
    return {
      kind: notGit ? "not-git" : "git-error",
      changedFiles: [],
      reason: notGit ? "target is not a git repository" : "git command failed",
      error: message,
    };
  }

  if (!state.hasCommits) {
    return {
      kind: "initial",
      state,
      ...(baseline ? { baseline } : {}),
      changedFiles: state.statusEntries,
      reason: "repository has no commits; initial full scan is required",
    };
  }

  const baselineDiff = baseline ? await diffFromBaseline(targetPath, baseline, state) : [];
  const merged = new Map<string, GitFileChange>();
  for (const change of [...baselineDiff, ...state.statusEntries]) {
    merged.set(`${change.status}:${change.oldPath ?? ""}:${change.path}`, change);
  }
  const changedFiles = [...merged.values()];

  if (!baseline) {
    return {
      kind: "initial",
      state,
      changedFiles,
      reason: "no previous git baseline exists",
    };
  }

  const unchanged =
    baseline.repoRoot === state.repoRoot &&
    baseline.headCommit === state.headCommit &&
    baseline.workingTreeFingerprint === state.workingTreeFingerprint;

  return {
    kind: unchanged ? "unchanged" : "changed",
    state,
    baseline,
    changedFiles,
    reason: unchanged ? "no git changes since last successful baseline" : "git state changed",
  };
}

export function baselineFromGitState(
  workspaceId: string,
  state: GitState,
  lastSuccessfulScanId?: string,
  scannedAt = new Date().toISOString(),
): BaselineRecord {
  return {
    schemaVersion: 1,
    workspaceId,
    repoRoot: state.repoRoot,
    ...(state.branch ? { branch: state.branch } : {}),
    ...(state.headCommit ? { headCommit: state.headCommit } : {}),
    ...(lastSuccessfulScanId ? { lastSuccessfulScanId } : {}),
    workingTreeFingerprint: state.workingTreeFingerprint,
    scannedAt,
  };
}
