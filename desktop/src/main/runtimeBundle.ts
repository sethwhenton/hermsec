import { app } from "electron";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  createVerifiedBundleExecutionLease,
  verifyBundledResourceIntegrity,
  type BundledResourceIntegrityAnchor,
  type VerifiedBundleExecutionLease,
} from "./bundledRuntimeIntegrity";
import { BUNDLED_RESOURCE_INTEGRITY } from "./generated/bundledIntegrity";

const mainDir = import.meta.dirname;
const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");

export const BUNDLED_SCANNER_COMMANDS = [
  "semgrep",
  "gitleaks",
  "trufflehog",
  "trivy",
  "checkov",
  "bandit",
  "osv-scanner",
  "pip-audit",
  "pmg",
  "retire",
  "spotbugs",
  "dependency-check",
  "psalm",
  "composer",
  "gosec",
  "govulncheck",
  "cargo",
  "brakeman",
  "flawfinder",
  "cppcheck",
  "dotnet",
] as const;

type ScannerCommand = (typeof BUNDLED_SCANNER_COMMANDS)[number];

const REQUIRED_RUNTIME_PROVENANCE_IDS = new Set([
  "runtime-assets",
  "python-lock-provenance",
  "python-direct-requirements",
  "python-platform-lock",
]);
const REQUIRED_BUNDLED_SCANNER_IDS = new Set([
  "semgrep",
  "gitleaks",
  "bandit",
  "osv-scanner",
  "pip-audit",
  "pmg",
]);
let bundledRuntimeIntegrityError: string | undefined;

export type BundledRuntimeExecutionLease = VerifiedBundleExecutionLease & {
  trustedEnvironment: Record<string, string>;
  controlledEnvironmentNames: string[];
};

export function configureBundledRuntime(): void {
  if (app.isPackaged) {
    clearInheritedPackagedRuntimeOverrides();
  }
  const toolsRoot = findBundledToolsRoot();
  if (toolsRoot) {
    try {
      if (app.isPackaged) {
        assertBundledRuntimeIntegrity(toolsRoot);
      }
      prependPath(toolPathEntries(toolsRoot));
      if (app.isPackaged) {
        process.env.HERMSEC_TOOLS_DIR = toolsRoot;
      } else {
        prependPathEnv("HERMSEC_TOOLS_DIR", [toolsRoot]);
      }
      process.env.HERMSEC_BUNDLED_TOOLS_DIR = toolsRoot;
      for (const command of BUNDLED_SCANNER_COMMANDS) {
        const executable = findBundledToolExecutable(toolsRoot, command);
        if (executable && (app.isPackaged || !process.env[scannerOverrideEnvName(command)])) {
          process.env[scannerOverrideEnvName(command)] = executable;
        }
      }
    } catch (error) {
      bundledRuntimeIntegrityError = error instanceof Error ? error.message : String(error);
      process.env.HERMSEC_BUNDLED_RUNTIME_INTEGRITY_ERROR = bundledRuntimeIntegrityError;
    }
  }

  const cliRoot = findBundledCliRoot();
  if (app.isPackaged && cliRoot) {
    process.env.HERMSEC_CLI_ROOT = cliRoot;
  }

  process.env.NO_COLOR ??= "1";
  process.env.SEMGREP_SEND_METRICS ??= "off";
  process.env.SEMGREP_ENABLE_VERSION_CHECK ??= "0";
  process.env.PMG_DISABLE_TELEMETRY ??= "true";
}

export function findBundledCliRoot(): string | undefined {
  if (app.isPackaged) {
    const candidate = path.join(process.resourcesPath, "hermsec-cli");
    return hasHermsecCli(candidate) ? candidate : undefined;
  }
  const configured = process.env.HERMSEC_CLI_ROOT?.trim();
  if (configured && hasHermsecCli(configured)) {
    return path.resolve(configured);
  }
  return undefined;
}

export function findBundledToolsRoot(): string | undefined {
  if (app.isPackaged) {
    const candidate = path.join(
      process.resourcesPath,
      "runtime-tools",
      `${process.platform}-${process.arch}`,
    );
    return existsSync(candidate) ? candidate : undefined;
  }
  const configured = process.env.HERMSEC_BUNDLED_TOOLS_DIR?.trim();
  if (configured && existsSync(configured)) {
    return path.resolve(configured);
  }
  return toolRootCandidates().find((candidate) => existsSync(candidate));
}

export function getBundledRuntimeIntegrityError(): string | undefined {
  return bundledRuntimeIntegrityError;
}

/**
 * Validates both mutable resource directories against the anchor embedded in the
 * Electron main bundle. The runtime manifest is validated only after this check.
 */
export function assertBundledRuntimeIntegrity(
  toolsRoot = findBundledToolsRoot(),
): string {
  const verified = verifyImmutableBundledResources();
  if (toolsRoot && path.resolve(toolsRoot) !== verified.toolsRoot) {
    throw new Error("Bundled runtime-tools path does not match the immutable packaged resource location.");
  }
  validateRuntimeManifest(verified.toolsRoot);
  return verified.toolsRoot;
}

/**
 * Each packaged Doctor/scan uses only this copy. If resource bytes change while
 * it is copied, snapshot verification fails. A final lease verification happens
 * immediately before every child process is spawned.
 */
export function createVerifiedBundledRuntimeExecutionLease(): BundledRuntimeExecutionLease {
  const anchor = immutableBundledResourceAnchor();
  const lease = createVerifiedBundleExecutionLease({
    resourcesRoot: process.resourcesPath,
    leaseParent: path.join(app.getPath("temp"), "hermsec-runtime-leases"),
    anchor,
  });
  validateRuntimeManifest(lease.toolsRoot);
  const trustedEnvironment: Record<string, string> = {
    HERMSEC_CLI_ROOT: lease.cliRoot,
    HERMSEC_TOOLS_DIR: lease.toolsRoot,
    HERMSEC_BUNDLED_TOOLS_DIR: lease.toolsRoot,
    // Do not let a scanner missing from the bundle fall through to a managed or
    // host executable. Child scanners are resolved from the verified lease only.
    PATH: path.join(lease.toolsRoot, "bin"),
    ...(process.platform === "win32" ? { PATHEXT: ".EXE" } : {}),
  };
  for (const command of BUNDLED_SCANNER_COMMANDS) {
    const executable = findBundledToolExecutable(lease.toolsRoot, command);
    if (executable) trustedEnvironment[scannerOverrideEnvName(command)] = executable;
  }
  return {
    ...lease,
    trustedEnvironment,
    controlledEnvironmentNames: [
      "HERMSEC_CLI_ROOT",
      "HERMSEC_TOOLS_DIR",
      "HERMSEC_BUNDLED_TOOLS_DIR",
      "PATH",
      "PATHEXT",
      "NODE_OPTIONS",
      "NODE_EXTRA_CA_CERTS",
      ...bundledScannerOverrideEnvironmentNames(),
    ],
  };
}

export function bundledScannerOverrideEnvironmentNames(): string[] {
  return BUNDLED_SCANNER_COMMANDS.map(scannerOverrideEnvName);
}

function verifyImmutableBundledResources() {
  return verifyBundledResourceIntegrity({
    resourcesRoot: process.resourcesPath,
    anchor: immutableBundledResourceAnchor(),
  });
}

function immutableBundledResourceAnchor(): BundledResourceIntegrityAnchor {
  const anchor = BUNDLED_RESOURCE_INTEGRITY as unknown;
  if (!anchor || typeof anchor !== "object") {
    throw new Error("Packaged Hermsec is missing its embedded resource integrity anchor. Reinstall a complete release build.");
  }
  return anchor as BundledResourceIntegrityAnchor;
}

function toolRootCandidates(): string[] {
  const platformKey = `${process.platform}-${process.arch}`;
  return unique([
    path.resolve(mainDir, "../../resources/runtime-tools", platformKey),
    path.resolve(process.cwd(), "resources/runtime-tools", platformKey),
  ]);
}

function hasHermsecCli(root: string): boolean {
  return existsSync(path.join(root, CLI_RELATIVE_PATH));
}

function toolPathEntries(toolsRoot: string): string[] {
  return [path.join(toolsRoot, "bin")].filter((entry) => existsSync(entry));
}

export function findBundledToolExecutable(toolsRoot: string, command: ScannerCommand): string | undefined {
  const executableName = process.platform === "win32" ? `${command}.exe` : command;
  const candidate = path.join(toolsRoot, "bin", executableName);
  return existsSync(candidate) ? candidate : undefined;
}

function scannerOverrideEnvName(command: ScannerCommand): string {
  return `HERMSEC_${command.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_BIN`;
}

function clearInheritedPackagedRuntimeOverrides(): void {
  const names = new Set([
    "HERMSEC_CLI_ROOT",
    "HERMSEC_BUNDLED_TOOLS_DIR",
    "HERMSEC_TOOLS_DIR",
    "HERMSEC_BUNDLED_RUNTIME_INTEGRITY_ERROR",
    ...bundledScannerOverrideEnvironmentNames(),
  ]);
  for (const key of Object.keys(process.env)) {
    if (names.has(key.toUpperCase())) {
      delete process.env[key];
    }
  }
  bundledRuntimeIntegrityError = undefined;
}

function validateRuntimeManifest(root: string): void {
  const manifestPath = path.join(root, "manifest.json");
  if (!existsSync(manifestPath) || !lstatSync(manifestPath).isFile()) {
    throw new Error("Bundled runtime manifest is missing.");
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    schemaVersion?: unknown;
    platform?: unknown;
    arch?: unknown;
    provenance?: unknown;
    tools?: unknown;
    files?: unknown;
    treeSha256?: unknown;
  };
  if (
    manifest.schemaVersion !== "4.0"
    || manifest.platform !== process.platform
    || manifest.arch !== process.arch
    || !Array.isArray(manifest.files)
    || typeof manifest.treeSha256 !== "string"
    || !/^[a-f0-9]{64}$/u.test(manifest.treeSha256)
  ) {
    throw new Error("Bundled runtime manifest has an unexpected schema or platform binding.");
  }
  validateRuntimeProvenance(root, manifest.provenance);
  validateRequiredScannerMetadata(manifest.tools);
}

function validateRuntimeProvenance(root: string, value: unknown): void {
  if (!Array.isArray(value)) {
    throw new Error("Bundled runtime manifest does not contain provenance entries.");
  }
  const remaining = new Set(REQUIRED_RUNTIME_PROVENANCE_IDS);
  const seen = new Set<string>();
  for (const entry of value) {
    if (!isRuntimeProvenanceEntry(entry) || seen.has(entry.id) || !isCanonicalRuntimePath(entry.path)) {
      throw new Error("Bundled runtime manifest contains malformed or duplicate provenance.");
    }
    seen.add(entry.id);
    const filePath = path.resolve(root, entry.path);
    const relative = path.relative(root, filePath);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative) || !existsSync(filePath) || !lstatSync(filePath).isFile()) {
      throw new Error(`Bundled runtime provenance ${entry.id} is missing.`);
    }
    const digest = createHash("sha256").update(readFileSync(filePath)).digest("hex");
    if (digest !== entry.sha256) {
      throw new Error(`Bundled runtime provenance hash mismatch for ${entry.id}.`);
    }
    remaining.delete(entry.id);
  }
  if (remaining.size > 0) {
    throw new Error(`Bundled runtime manifest is missing provenance: ${[...remaining].join(", ")}.`);
  }
}

function validateRequiredScannerMetadata(value: unknown): void {
  if (!Array.isArray(value)) {
    throw new Error("Bundled runtime manifest has no scanner metadata.");
  }
  const ids = new Set(
    value
      .filter((entry): entry is { id: string } =>
        Boolean(entry && typeof entry === "object" && typeof (entry as { id?: unknown }).id === "string"))
      .map((entry) => entry.id),
  );
  const missing = [...REQUIRED_BUNDLED_SCANNER_IDS].filter((id) => !ids.has(id));
  if (missing.length > 0) {
    throw new Error(`Bundled runtime manifest is missing scanners: ${missing.join(", ")}.`);
  }
}

function isRuntimeProvenanceEntry(value: unknown): value is { id: string; path: string; sha256: string } {
  return Boolean(
    value
    && typeof value === "object"
    && typeof (value as { id?: unknown }).id === "string"
    && typeof (value as { path?: unknown }).path === "string"
    && /^[a-f0-9]{64}$/u.test(String((value as { sha256?: unknown }).sha256 ?? "")),
  );
}

function isCanonicalRuntimePath(value: string): boolean {
  if (!value || value.includes("\\") || value.includes("\0") || path.posix.isAbsolute(value)) {
    return false;
  }
  const normalized = path.posix.normalize(value);
  return normalized === value && normalized !== "." && !normalized.startsWith("../");
}

function prependPath(entries: string[]): void {
  prependPathEnv("PATH", entries);
}

function prependPathEnv(name: string, entries: string[]): void {
  const current = process.env[name] ?? "";
  const existing = current.split(path.delimiter).filter(Boolean);
  process.env[name] = unique([...entries, ...existing]).join(path.delimiter);
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => path.resolve(value))));
}
