import fs from "node:fs/promises";
import path from "node:path";
import { toPosixPath } from "../shared/paths.js";

export const DEFAULT_IGNORES = new Set([
  ".git",
  "node_modules",
  "vendor",
  "venv",
  ".venv",
  "dist",
  "build",
  "coverage",
  ".hermsec",
  ".next",
  ".nuxt",
  ".cache",
  "__pycache__",
]);

const TEXT_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".java",
  ".jsp",
  ".json",
  ".xml",
  ".yml",
  ".yaml",
  ".toml",
  ".properties",
  ".gradle",
  ".ini",
  ".conf",
  ".md",
  ".txt",
]);

const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "poetry.lock",
  "uv.lock",
  "Pipfile.lock",
  "Cargo.lock",
  "go.sum",
  "gradle.lockfile",
]);

export type SourceLanguage =
  | "javascript"
  | "typescript"
  | "python"
  | "java"
  | "jsp"
  | "json"
  | "xml"
  | "yaml"
  | "toml"
  | "properties"
  | "gradle"
  | "text"
  | "unknown";

export type SourceFile = {
  absolutePath: string;
  relativePath: string;
  extension: string;
  baseName: string;
  size: number;
  language: SourceLanguage;
  kind: "source" | "manifest" | "lockfile" | "config" | "text";
};

export type IgnoredDirectory = {
  name: string;
  count: number;
};

export type WalkResult = {
  files: SourceFile[];
  ignoredDirectories: IgnoredDirectory[];
  truncated: boolean;
};

export type WalkOptions = {
  maxFiles?: number;
  maxTextFileBytes?: number;
  maxLockfileBytes?: number;
};

export async function assertDirectory(target: string): Promise<void> {
  let stats;
  try {
    stats = await fs.stat(target);
  } catch {
    throw new Error(`Target does not exist: ${target}`);
  }
  if (!stats.isDirectory()) {
    throw new Error(`Target must be a directory: ${target}`);
  }
}

export async function walkSourceFiles(root: string, options: WalkOptions = {}): Promise<SourceFile[]> {
  return (await walkSourceTree(root, options)).files;
}

export async function walkSourceTree(root: string, options: WalkOptions = {}): Promise<WalkResult> {
  const files: SourceFile[] = [];
  const ignoredCounts = new Map<string, number>();
  const pending = [root];
  const maxFiles = options.maxFiles ?? 25_000;
  const maxTextFileBytes = options.maxTextFileBytes ?? 1_500_000;
  const maxLockfileBytes = options.maxLockfileBytes ?? 5_000_000;

  while (pending.length > 0) {
    const dir = pending.pop();
    if (!dir) {
      continue;
    }

    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const absolutePath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (DEFAULT_IGNORES.has(entry.name)) {
          increment(ignoredCounts, entry.name);
          continue;
        }
        pending.push(absolutePath);
        continue;
      }

      if (entry.isSymbolicLink()) {
        increment(ignoredCounts, "symlink");
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }

      const file = await describeFile(root, absolutePath, entry.name);
      if (!shouldInclude(file, maxTextFileBytes, maxLockfileBytes)) {
        continue;
      }

      files.push(file);
      if (files.length >= maxFiles) {
        increment(ignoredCounts, "max-file-limit");
        return {
          files: sortFiles(files),
          ignoredDirectories: ignoredEntries(ignoredCounts),
          truncated: true,
        };
      }
    }
  }

  return {
    files: sortFiles(files),
    ignoredDirectories: ignoredEntries(ignoredCounts),
    truncated: false,
  };
}

export async function readTextFile(file: SourceFile): Promise<string> {
  const buffer = await fs.readFile(file.absolutePath);
  if (buffer.includes(0)) {
    throw new Error(`Skipping binary-like file: ${file.relativePath}`);
  }
  return buffer.toString("utf8");
}

function shouldInclude(file: SourceFile, maxTextFileBytes: number, maxLockfileBytes: number): boolean {
  if (file.kind === "lockfile") {
    return file.size <= maxLockfileBytes;
  }
  if (file.size > maxTextFileBytes) {
    return false;
  }
  return file.kind !== "text" || file.language !== "unknown";
}

async function describeFile(root: string, absolutePath: string, fileName: string): Promise<SourceFile> {
  const stats = await fs.stat(absolutePath);
  const baseName = path.basename(fileName);
  const extension = path.extname(fileName).toLowerCase();
  const language = languageFor(baseName, extension);
  return {
    absolutePath,
    relativePath: toPosixPath(path.relative(root, absolutePath)),
    extension,
    baseName,
    size: stats.size,
    language,
    kind: kindFor(baseName, language),
  };
}

function languageFor(baseName: string, extension: string): SourceLanguage {
  if (baseName.startsWith(".env") || baseName === "Dockerfile" || baseName.endsWith(".conf") || baseName.endsWith(".ini")) {
    return "text";
  }
  if (baseName.endsWith(".gradle.kts")) {
    return "gradle";
  }
  switch (extension) {
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".ts":
    case ".tsx":
    case ".mts":
    case ".cts":
      return "typescript";
    case ".py":
      return "python";
    case ".java":
      return "java";
    case ".jsp":
      return "jsp";
    case ".json":
      return "json";
    case ".xml":
      return "xml";
    case ".yml":
    case ".yaml":
      return "yaml";
    case ".toml":
      return "toml";
    case ".properties":
      return "properties";
    case ".gradle":
      return "gradle";
    case ".md":
    case ".txt":
      return "text";
    default:
      return TEXT_EXTENSIONS.has(extension) || LOCKFILE_NAMES.has(baseName) ? "text" : "unknown";
  }
}

function kindFor(baseName: string, language: SourceLanguage): SourceFile["kind"] {
  if (LOCKFILE_NAMES.has(baseName)) {
    return "lockfile";
  }
  if ([
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "build.gradle.kts",
    "settings.gradle.kts",
  ].includes(baseName)) {
    return "manifest";
  }
  if (
    baseName.startsWith(".env") ||
    baseName === "Dockerfile" ||
    language === "yaml" ||
    language === "toml" ||
    language === "json" ||
    language === "xml" ||
    language === "properties" ||
    language === "gradle"
  ) {
    return "config";
  }
  if (language === "javascript" || language === "typescript" || language === "python" || language === "java" || language === "jsp") {
    return "source";
  }
  return "text";
}

function increment(counts: Map<string, number>, name: string): void {
  counts.set(name, (counts.get(name) ?? 0) + 1);
}

function ignoredEntries(counts: Map<string, number>): IgnoredDirectory[] {
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function sortFiles(files: SourceFile[]): SourceFile[] {
  return files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}
