import path from "node:path";
import type {
  CodeInspectionFile,
  CodeInspectionRuntime,
} from "./codeInspection.js";

export type ProjectCapability =
  | "authentication"
  | "ci"
  | "cloud-storage"
  | "container"
  | "cryptography"
  | "database"
  | "dependency-management"
  | "file-upload"
  | "http-api"
  | "infrastructure-as-code"
  | "process-execution"
  | "sensitive-config"
  | "template-rendering";

export type ProjectProfileFile = CodeInspectionFile;

export type ProjectLanguageProfile = {
  language: CodeInspectionFile["language"];
  fileCount: number;
  sourceFileCount: number;
  bytes: number;
};

export type ProjectManifestProfile = {
  path: string;
  ecosystem: string;
  readable: boolean;
  technologies: string[];
};

export type ProjectCapabilitySignal = {
  id: ProjectCapability;
  evidence: string[];
};

export type ProjectProfile = {
  schemaVersion: "1.0";
  repoRoot: string;
  files: ProjectProfileFile[];
  fileSummary: {
    total: number;
    source: number;
    manifest: number;
    lockfile: number;
    config: number;
    text: number;
    bytes: number;
    truncated: boolean;
  };
  languages: ProjectLanguageProfile[];
  ecosystems: string[];
  manifests: ProjectManifestProfile[];
  technologies: string[];
  frameworks: string[];
  capabilities: ProjectCapabilitySignal[];
  limitations: string[];
};

export type ProjectProfilerOptions = {
  maxFiles?: number;
  maxManifests?: number;
  maxManifestChars?: number;
};

type TechnologyPattern = {
  id: string;
  aliases: readonly string[];
  kind: "framework" | "library" | "platform";
  capabilities: readonly ProjectCapability[];
};

const DEFAULT_MAX_FILES = 5_000;
const DEFAULT_MAX_MANIFESTS = 40;
const DEFAULT_MAX_MANIFEST_CHARS = 16_000;

const TECHNOLOGY_PATTERNS: readonly TechnologyPattern[] = [
  technology("express", ["express"], "framework", ["http-api", "template-rendering"]),
  technology("fastify", ["fastify"], "framework", ["http-api"]),
  technology("koa", ["\"koa\"", "'koa'"], "framework", ["http-api"]),
  technology("nestjs", ["@nestjs/"], "framework", ["http-api", "authentication"]),
  technology("nextjs", ["\"next\"", "'next'"], "framework", ["http-api", "template-rendering"]),
  technology("react", ["\"react\"", "'react'"], "framework", ["template-rendering"]),
  technology("vue", ["\"vue\"", "'vue'"], "framework", ["template-rendering"]),
  technology("svelte", ["svelte"], "framework", ["template-rendering"]),
  technology("flask", ["flask"], "framework", ["http-api", "template-rendering"]),
  technology("django", ["django"], "framework", ["http-api", "authentication", "database", "template-rendering"]),
  technology("fastapi", ["fastapi"], "framework", ["http-api"]),
  technology("spring", ["spring-boot", "org.springframework"], "framework", ["http-api", "authentication", "database"]),
  technology("rails", ["rails"], "framework", ["http-api", "authentication", "database", "template-rendering"]),
  technology("laravel", ["laravel/framework"], "framework", ["http-api", "authentication", "database", "template-rendering"]),
  technology("gin", ["github.com/gin-gonic/gin"], "framework", ["http-api"]),
  technology("actix-web", ["actix-web"], "framework", ["http-api"]),
  technology("aspnet", ["microsoft.aspnetcore"], "framework", ["http-api", "authentication"]),
  technology("passport", ["passport"], "library", ["authentication"]),
  technology("jsonwebtoken", ["jsonwebtoken"], "library", ["authentication", "cryptography"]),
  technology("jose", ["\"jose\"", "'jose'"], "library", ["authentication", "cryptography"]),
  technology("oauth", ["oauth", "openid", "authlib"], "library", ["authentication"]),
  technology("bcrypt", ["bcrypt"], "library", ["authentication", "cryptography"]),
  technology("argon2", ["argon2"], "library", ["authentication", "cryptography"]),
  technology("helmet", ["helmet"], "library", ["http-api"]),
  technology("cors", ["\"cors\"", "'cors'"], "library", ["http-api"]),
  technology("csrf", ["csrf", "csurf"], "library", ["http-api", "authentication"]),
  technology("prisma", ["@prisma/", "\"prisma\""], "library", ["database"]),
  technology("sequelize", ["sequelize"], "library", ["database"]),
  technology("typeorm", ["typeorm"], "library", ["database"]),
  technology("mongoose", ["mongoose"], "library", ["database"]),
  technology("knex", ["\"knex\"", "'knex'"], "library", ["database"]),
  technology("sqlalchemy", ["sqlalchemy"], "library", ["database"]),
  technology("postgres", ["psycopg", "\"pg\"", "'pg'"], "library", ["database"]),
  technology("mysql", ["mysql2", "pymysql", "mysqlclient"], "library", ["database"]),
  technology("sqlite", ["sqlite3", "better-sqlite3", "aiosqlite"], "library", ["database"]),
  technology("redis", ["redis", "ioredis"], "library", ["database"]),
  technology("ejs", ["\"ejs\"", "'ejs'"], "library", ["template-rendering"]),
  technology("handlebars", ["handlebars"], "library", ["template-rendering"]),
  technology("jinja", ["jinja"], "library", ["template-rendering"]),
  technology("multer", ["multer"], "library", ["file-upload"]),
  technology("shelljs", ["shelljs"], "library", ["process-execution"]),
  technology("execa", ["execa"], "library", ["process-execution"]),
  technology("aws-sdk", ["aws-sdk", "@aws-sdk/", "boto3"], "platform", ["cloud-storage"]),
  technology("azure-sdk", ["@azure/", "azure-storage"], "platform", ["cloud-storage"]),
  technology("google-cloud", ["@google-cloud/", "google-cloud-storage"], "platform", ["cloud-storage"]),
  technology("firebase", ["firebase"], "platform", ["cloud-storage", "authentication"]),
  technology("supabase", ["supabase"], "platform", ["cloud-storage", "authentication", "database"]),
] as const;

export async function profileProject(
  runtime: CodeInspectionRuntime,
  options: ProjectProfilerOptions = {},
): Promise<ProjectProfile> {
  const maxFiles = boundedInt(options.maxFiles, DEFAULT_MAX_FILES, 1, DEFAULT_MAX_FILES);
  const maxManifests = boundedInt(options.maxManifests, DEFAULT_MAX_MANIFESTS, 0, 200);
  const maxManifestChars = boundedInt(
    options.maxManifestChars,
    DEFAULT_MAX_MANIFEST_CHARS,
    500,
    20_000,
  );
  const files = runtime.listFiles({ limit: maxFiles })
    .map((file) => ({ ...file }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const manifestFiles = files
    .filter((file) => file.kind === "manifest")
    .slice(0, maxManifests);
  const manifests: ProjectManifestProfile[] = [];
  const limitations: string[] = [];
  const capabilityEvidence = new Map<ProjectCapability, Set<string>>();
  const technologies = new Set<string>();
  const frameworks = new Set<string>();
  const profileTruncated = runtime.profile.truncated
    || runtime.profile.indexedFiles > files.length;

  if (profileTruncated) {
    limitations.push(`Project profile reached the ${maxFiles}-file metadata limit.`);
  }
  if (files.filter((file) => file.kind === "manifest").length > maxManifests) {
    limitations.push(`Project profile read only the first ${maxManifests} manifests.`);
  }

  for (const file of manifestFiles) {
    const ecosystem = ecosystemForManifest(file.path);
    let manifestText = "";
    let readable = true;
    try {
      const snippet = await runtime.readFileSnippet({
        path: file.path,
        startLine: 1,
        endLine: 160,
        maxChars: maxManifestChars,
      });
      manifestText = stripSnippetLineNumbers(snippet.text).toLowerCase();
      if (snippet.truncated) {
        limitations.push(`Manifest profile was truncated for ${file.path}.`);
      }
    } catch {
      readable = false;
      limitations.push(`Manifest metadata could not be read for ${file.path}.`);
    }

    const detected = detectTechnologies(manifestText);
    for (const item of detected) {
      technologies.add(item.id);
      if (item.kind === "framework") {
        frameworks.add(item.id);
      }
      for (const capability of item.capabilities) {
        addCapabilityEvidence(
          capabilityEvidence,
          capability,
          `manifest:${file.path}:${item.id}`,
        );
      }
    }
    manifests.push({
      path: file.path,
      ecosystem,
      readable,
      technologies: detected.map((item) => item.id),
    });
  }

  deriveMetadataSignals(files, capabilityEvidence);
  if (files.some((file) => file.kind === "manifest" || file.kind === "lockfile")) {
    addCapabilityEvidence(
      capabilityEvidence,
      "dependency-management",
      "metadata:manifest-or-lockfile",
    );
  }

  return {
    schemaVersion: "1.0",
    repoRoot: runtime.repoRoot,
    files,
    fileSummary: summarizeFiles(files, profileTruncated),
    languages: summarizeLanguages(files),
    ecosystems: uniqueSorted(manifests.map((manifest) => manifest.ecosystem)),
    manifests: manifests.sort((left, right) => left.path.localeCompare(right.path)),
    technologies: [...technologies].sort(),
    frameworks: [...frameworks].sort(),
    capabilities: [...capabilityEvidence.entries()]
      .map(([id, evidence]) => ({ id, evidence: [...evidence].sort() }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    limitations: uniqueSorted(limitations),
  };
}

export function hasProjectCapability(
  profile: ProjectProfile,
  capability: ProjectCapability,
): boolean {
  return profile.capabilities.some((signal) => signal.id === capability);
}

function deriveMetadataSignals(
  files: readonly ProjectProfileFile[],
  evidence: Map<ProjectCapability, Set<string>>,
): void {
  for (const file of files) {
    const lowerPath = file.path.toLowerCase();
    const baseName = path.posix.basename(lowerPath);
    const metadataEvidence = `path:${file.path}`;

    if (
      includesPathPart(lowerPath, ["routes", "controllers", "api", "endpoints"])
      || /(?:^|\/)(?:app|server|main)\.(?:js|ts|py|go|rb|php|java)$/u.test(lowerPath)
    ) {
      addCapabilityEvidence(evidence, "http-api", metadataEvidence);
    }
    if (includesPathPart(lowerPath, ["auth", "login", "session", "middleware"])) {
      addCapabilityEvidence(evidence, "authentication", metadataEvidence);
    }
    if (includesPathPart(lowerPath, ["db", "database", "models", "migrations", "repositories"])) {
      addCapabilityEvidence(evidence, "database", metadataEvidence);
    }
    if (
      includesPathPart(lowerPath, ["views", "templates"])
      || ["html", "vue", "svelte"].includes(file.language)
    ) {
      addCapabilityEvidence(evidence, "template-rendering", metadataEvidence);
    }
    if (includesPathPart(lowerPath, ["upload", "uploads", "attachments"])) {
      addCapabilityEvidence(evidence, "file-upload", metadataEvidence);
    }
    if (
      file.kind === "config"
      || includesPathPart(lowerPath, ["config", "settings", "secrets"])
    ) {
      addCapabilityEvidence(evidence, "sensitive-config", metadataEvidence);
    }
    if (
      lowerPath.startsWith(".github/workflows/")
      || lowerPath === ".gitlab-ci.yml"
      || lowerPath.startsWith(".circleci/")
    ) {
      addCapabilityEvidence(evidence, "ci", metadataEvidence);
    }
    if (
      baseName === "dockerfile"
      || baseName.startsWith("docker-compose")
      || lowerPath.includes("/docker/")
    ) {
      addCapabilityEvidence(evidence, "container", metadataEvidence);
    }
    if (
      file.language === "terraform"
      || includesPathPart(lowerPath, ["terraform", "kubernetes", "k8s", "helm"])
    ) {
      addCapabilityEvidence(evidence, "infrastructure-as-code", metadataEvidence);
    }
    if (includesPathPart(lowerPath, ["storage", "buckets", "s3"])) {
      addCapabilityEvidence(evidence, "cloud-storage", metadataEvidence);
    }
    if (includesPathPart(lowerPath, ["crypto", "encryption", "keys"])) {
      addCapabilityEvidence(evidence, "cryptography", metadataEvidence);
    }
  }
}

function detectTechnologies(text: string): TechnologyPattern[] {
  if (!text) {
    return [];
  }
  return TECHNOLOGY_PATTERNS
    .filter((item) => item.aliases.some((alias) => text.includes(alias.toLowerCase())))
    .map((item) => ({
      ...item,
      aliases: [...item.aliases],
      capabilities: [...item.capabilities],
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
}

function summarizeFiles(
  files: readonly ProjectProfileFile[],
  truncated: boolean,
): ProjectProfile["fileSummary"] {
  return {
    total: files.length,
    source: files.filter((file) => file.kind === "source").length,
    manifest: files.filter((file) => file.kind === "manifest").length,
    lockfile: files.filter((file) => file.kind === "lockfile").length,
    config: files.filter((file) => file.kind === "config").length,
    text: files.filter((file) => file.kind === "text").length,
    bytes: files.reduce((total, file) => total + file.size, 0),
    truncated,
  };
}

function summarizeLanguages(
  files: readonly ProjectProfileFile[],
): ProjectLanguageProfile[] {
  const summaries = new Map<
    CodeInspectionFile["language"],
    Omit<ProjectLanguageProfile, "language">
  >();
  for (const file of files) {
    const current = summaries.get(file.language) ?? {
      fileCount: 0,
      sourceFileCount: 0,
      bytes: 0,
    };
    current.fileCount += 1;
    current.sourceFileCount += file.kind === "source" ? 1 : 0;
    current.bytes += file.size;
    summaries.set(file.language, current);
  }
  return [...summaries.entries()]
    .map(([language, summary]) => ({ language, ...summary }))
    .sort(
      (left, right) =>
        right.sourceFileCount - left.sourceFileCount
        || right.fileCount - left.fileCount
        || left.language.localeCompare(right.language),
    );
}

function ecosystemForManifest(filePath: string): string {
  const baseName = path.posix.basename(filePath);
  if (
    baseName === "package.json"
    || baseName === "package-lock.json"
    || baseName === "pnpm-lock.yaml"
    || baseName === "yarn.lock"
    || baseName === "bun.lock"
    || baseName === "bun.lockb"
  ) {
    return "npm";
  }
  if (
    baseName === "pyproject.toml"
    || baseName === "requirements.txt"
    || baseName === "requirements-dev.txt"
    || baseName === "Pipfile"
  ) {
    return "python";
  }
  if (baseName === "go.mod") return "go";
  if (baseName === "Cargo.toml") return "rust";
  if (baseName === "composer.json") return "php";
  if (baseName === "Gemfile") return "ruby";
  if (baseName === "pom.xml" || baseName.startsWith("build.gradle")) return "jvm";
  if (baseName.endsWith(".csproj") || baseName.endsWith(".sln")) return "dotnet";
  return "unknown";
}

function stripSnippetLineNumbers(text: string): string {
  return text
    .split(/\r?\n/u)
    .map((line) => line.replace(/^\d+:\s?/u, ""))
    .join("\n");
}

function includesPathPart(filePath: string, parts: readonly string[]): boolean {
  const segments = filePath.split("/");
  return parts.some((part) => segments.some((segment) => segment.includes(part)));
}

function addCapabilityEvidence(
  signals: Map<ProjectCapability, Set<string>>,
  capability: ProjectCapability,
  value: string,
): void {
  const evidence = signals.get(capability) ?? new Set<string>();
  evidence.add(value);
  signals.set(capability, evidence);
}

function technology(
  id: string,
  aliases: readonly string[],
  kind: TechnologyPattern["kind"],
  capabilities: readonly ProjectCapability[],
): TechnologyPattern {
  return { id, aliases, kind, capabilities };
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function boundedInt(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}
