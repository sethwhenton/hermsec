import path from "node:path";
import type { ChangeBucket, ChangeClassification, GitFileChange, ScanScope } from "./types.js";

const dependencyFiles = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "requirements.txt",
  "requirements-dev.txt",
  "pyproject.toml",
  "poetry.lock",
  "pipfile",
  "pipfile.lock",
  "go.mod",
  "go.sum",
  "cargo.toml",
  "cargo.lock",
  "gemfile",
  "gemfile.lock",
  "composer.json",
  "composer.lock",
]);

const sourceExtensions = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".rs",
  ".java",
  ".cs",
  ".php",
  ".rb",
  ".swift",
  ".kt",
  ".kts",
]);

const docsExtensions = new Set([
  ".md",
  ".mdx",
  ".txt",
  ".rst",
  ".adoc",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".svg",
  ".pptx",
  ".docx",
  ".pdf",
]);

const securityPathPattern =
  /(^|\/)(auth|authentication|authorization|session|sessions|token|tokens|permission|permissions|middleware|security|crypto|cryptography|secrets?|config|configs?|dockerfile|docker-compose\.ya?ml|compose\.ya?ml|\.github\/workflows|\.env\.example|terraform|infra|iac)(\/|$|\.)/i;

const generatedVendorPattern =
  /(^|\/)(node_modules|dist|build|coverage|\.next|\.nuxt|\.venv|venv|vendor|target|out|tmp|\.git)(\/|$)/i;

function normalizeFilePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function classifyPath(filePath: string): ChangeBucket {
  const normalized = normalizeFilePath(filePath);
  const basename = path.posix.basename(normalized).toLowerCase();
  const extension = path.posix.extname(normalized).toLowerCase();

  if (generatedVendorPattern.test(normalized)) {
    return "generated-vendor";
  }

  if (dependencyFiles.has(basename)) {
    return "dependency";
  }

  if (securityPathPattern.test(normalized)) {
    return "security-sensitive";
  }

  if (normalized.startsWith("docs/") || docsExtensions.has(extension)) {
    return "docs-only";
  }

  if (sourceExtensions.has(extension)) {
    return "source";
  }

  return "other";
}

function chooseScanScope(buckets: Set<ChangeBucket>): ScanScope {
  if (buckets.size === 0) {
    return "none";
  }
  if (buckets.has("security-sensitive")) {
    return "full";
  }
  if (buckets.has("dependency")) {
    return "dependency";
  }
  if (buckets.has("source") || buckets.has("other")) {
    return "changed-files";
  }
  return "none";
}

export function classifyChangedFiles(changes: GitFileChange[] | string[]): ChangeClassification {
  const paths = changes.map((change) => (typeof change === "string" ? change : change.path));
  const effectiveBuckets = new Set<ChangeBucket>();
  const ignoredFiles: string[] = [];
  const effectiveFiles: string[] = [];

  for (const filePath of paths) {
    const normalized = normalizeFilePath(filePath);
    const bucket = classifyPath(normalized);
    if (bucket === "generated-vendor") {
      ignoredFiles.push(normalized);
      continue;
    }
    effectiveFiles.push(normalized);
    effectiveBuckets.add(bucket);
  }

  return {
    changedFiles: paths.map(normalizeFilePath),
    effectiveFiles,
    ignoredFiles,
    buckets: [...effectiveBuckets],
    scanScope: chooseScanScope(effectiveBuckets),
  };
}
