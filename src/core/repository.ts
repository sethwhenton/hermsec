import { execFile } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import type { IgnoredDirectory, SourceFile } from "./files.js";

const execFileAsync = promisify(execFile);

export type GitMetadata = {
  branch?: string;
  commit?: string;
  dirty?: boolean;
};

export type RepositoryMetadata = {
  git: GitMetadata;
  sourceCounts: Record<SourceFile["language"], number>;
  packageManagers: string[];
  manifests: string[];
  lockfiles: string[];
  ignoredDirectories: IgnoredDirectory[];
};

async function git(root: string, args: string[]): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", root, ...args], {
      timeout: 5000,
      windowsHide: true,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
      },
    });
    return stdout.trim();
  } catch {
    return undefined;
  }
}

export async function getGitMetadata(root: string): Promise<GitMetadata> {
  const inside = await git(root, ["rev-parse", "--is-inside-work-tree"]);
  if (inside !== "true") {
    return {};
  }

  const branch = await git(root, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const commit = await git(root, ["rev-parse", "HEAD"]);
  const status = await git(root, ["status", "--porcelain=v1"]);
  const metadata: GitMetadata = {};

  if (branch && branch !== "HEAD") {
    metadata.branch = branch;
  }
  if (commit && /^[a-f0-9]{40}$/i.test(commit)) {
    metadata.commit = commit;
  }
  metadata.dirty = Boolean(status);
  return metadata;
}

export async function getGitHead(root: string): Promise<string | undefined> {
  return git(root, ["rev-parse", "HEAD"]);
}

export async function discoverRepositoryMetadata(
  root: string,
  files: SourceFile[],
  ignoredDirectories: IgnoredDirectory[],
): Promise<RepositoryMetadata> {
  const sourceCounts: RepositoryMetadata["sourceCounts"] = {
    javascript: 0,
    typescript: 0,
    python: 0,
    java: 0,
    jsp: 0,
    json: 0,
    xml: 0,
    yaml: 0,
    toml: 0,
    properties: 0,
    gradle: 0,
    text: 0,
    unknown: 0,
  };
  const packageManagers = new Set<string>();
  const manifests = new Set<string>();
  const lockfiles = new Set<string>();

  for (const file of files) {
    sourceCounts[file.language] += 1;
    if (file.kind === "manifest") {
      manifests.add(file.relativePath);
    }
    if (file.kind === "lockfile") {
      lockfiles.add(file.relativePath);
    }
    detectPackageManager(file, packageManagers);
  }

  return {
    git: await getGitMetadata(root),
    sourceCounts,
    packageManagers: [...packageManagers].sort(),
    manifests: [...manifests].sort(),
    lockfiles: [...lockfiles].sort(),
    ignoredDirectories,
  };
}

export function repositoryDiscoveryMessage(metadata: RepositoryMetadata, scannedFiles: number, truncated: boolean): string {
  const languages = Object.entries(metadata.sourceCounts)
    .filter(([, count]) => count > 0)
    .map(([language, count]) => `${language}:${count}`)
    .join(", ");
  const packageManagers = metadata.packageManagers.length > 0 ? metadata.packageManagers.join(", ") : "none";
  const lockfiles = metadata.lockfiles.length;
  const ignored = metadata.ignoredDirectories.map((item) => `${item.name}:${item.count}`).join(", ") || "none";
  const suffix = truncated ? " File walk hit the configured limit." : "";
  return `Discovered ${scannedFiles} files (${languages || "no recognized source languages"}), package managers: ${packageManagers}, lockfiles: ${lockfiles}, ignored folders: ${ignored}.${suffix}`;
}

function detectPackageManager(file: SourceFile, packageManagers: Set<string>): void {
  switch (path.posix.basename(file.relativePath)) {
    case "package.json":
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      packageManagers.add("npm");
      break;
    case "pnpm-lock.yaml":
      packageManagers.add("pnpm");
      break;
    case "yarn.lock":
      packageManagers.add("yarn");
      break;
    case "bun.lock":
    case "bun.lockb":
      packageManagers.add("bun");
      break;
    case "requirements.txt":
    case "requirements-dev.txt":
    case "Pipfile":
      packageManagers.add("pip");
      break;
    case "pyproject.toml":
    case "poetry.lock":
      packageManagers.add("python");
      break;
    case "uv.lock":
      packageManagers.add("uv");
      break;
    case "pom.xml":
      packageManagers.add("maven");
      break;
    case "build.gradle":
    case "settings.gradle":
    case "build.gradle.kts":
    case "settings.gradle.kts":
    case "gradle.lockfile":
      packageManagers.add("gradle");
      break;
  }
}
