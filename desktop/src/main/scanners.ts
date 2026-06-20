import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { app } from "electron";
import type {
  ScannerActionResult,
  ScannerCatalogItem,
  ScannerListRequest,
  ScannerSettings,
  ScannerStatusItem,
} from "../renderer/src/types/scanners";
import { readSettings, updateSettings } from "./store";

const scannerCatalog: ScannerCatalogItem[] = [
  item("hermsec-heuristics", "HermSec heuristics", "built-in", "built-in", ["all"], ["source", "config", "manifest", "lockfile"], "hermsec", true, false, "Built into HermSec. Runs deterministic local checks without external processes."),
  item("semgrep", "Semgrep", "sast", "python", ["javascript", "typescript", "java", "jsp", "python", "go", "php", "ruby", "rust", "c", "cpp", "csharp", "html", "terraform", "yaml"], ["source", "config"], "semgrep-json", true, true, "Runs local rules only with metrics disabled.", "semgrep", "1.167.0"),
  item("gitleaks", "Gitleaks", "secrets", "native", ["all"], ["source", "config", "git"], "gitleaks-json", true, true, "Runs with redaction enabled; raw secrets are not persisted.", "gitleaks", "v8.30.1"),
  item("trufflehog", "TruffleHog", "secrets", "go", ["all"], ["source", "git"], "trufflehog-jsonl", false, false, "Deeper secret scan. Verification stays disabled by default.", "trufflehog", "v3.90.8"),
  item("osv-scanner", "OSV-Scanner", "sca", "native", ["javascript", "typescript", "python", "java", "go", "rust", "php", "ruby"], ["lockfile", "sbom"], "osv-json", true, true, "Queries OSV advisory data for supported lockfiles and SBOMs.", "osv-scanner", "v2.4.0"),
  item("trivy", "Trivy", "sca", "native", ["all"], ["filesystem", "lockfile", "iac", "container"], "trivy-json", true, true, "Filesystem scans use vulnerability, secret, and misconfiguration scanners.", "trivy", "v0.66.0"),
  item("checkov", "Checkov", "iac", "python", ["terraform", "yaml", "dockerfile"], ["iac", "workflow", "dockerfile"], "checkov-json", true, true, "Static IaC scanner; does not run infrastructure commands.", "checkov", "3.2.471"),
  item("bandit", "Bandit", "sast", "python", ["python"], ["source"], "bandit-json", true, true, "Python AST security linter.", "bandit", "1.9.4"),
  item("pip-audit", "pip-audit", "sca", "python", ["python"], ["requirements.txt"], "pip-audit-json", true, true, "Runs only against pinned requirements in HermSec scans.", "pip-audit", "2.10.1"),
  item("pmg", "SafeDep PMG npm audit", "sca", "native", ["javascript", "typescript"], ["package-lock.json"], "npm-audit-json", true, true, "Wraps npm audit with install/fix/script commands blocked.", "pmg", "v0.19.1"),
  item("retire", "Retire.js", "sca", "npm", ["javascript", "typescript", "html"], ["source", "package.json"], "retire-json", true, false, "Detects vulnerable JavaScript libraries, including vendored frontend assets.", "retire", "5.2.7"),
  item("findsecbugs", "FindSecBugs / SpotBugs", "sast", "system", ["java", "jsp", "kotlin"], ["compiled-classes"], "spotbugs-json", true, false, "Requires compiled classes; HermSec does not build projects automatically.", "spotbugs", "4.9.3"),
  item("dependency-check", "OWASP Dependency-Check", "sca", "system", ["java", "javascript", "typescript", "python", "ruby", "dotnet"], ["manifest", "lockfile"], "dependency-check-json", true, false, "Uses vulnerability databases and may require a warm local cache.", "dependency-check", "12.1.8"),
  item("psalm", "Psalm taint analysis", "sast", "system", ["php"], ["source", "composer.json"], "psalm-json", true, false, "Runs taint analysis when Psalm is already available.", "psalm", "6.13.1"),
  item("composer-audit", "Composer audit", "sca", "system", ["php"], ["composer.lock"], "composer-audit-json", true, false, "Reads Composer advisories from the lockfile; does not install packages.", "composer"),
  item("gosec", "gosec", "sast", "go", ["go"], ["source", "go.mod"], "gosec-json", true, false, "Go AST/SSA security scanner.", "gosec", "v2.22.8"),
  item("govulncheck", "govulncheck", "sca", "go", ["go"], ["go.mod", "source"], "govulncheck-jsonl", true, false, "Official Go vulnerability checker.", "govulncheck", "v1.1.4"),
  item("cargo-audit", "cargo-audit", "sca", "cargo", ["rust"], ["Cargo.lock"], "cargo-audit-json", true, false, "Audits Cargo.lock against RustSec advisories.", "cargo", "0.21.2"),
  item("brakeman", "Brakeman", "sast", "system", ["ruby"], ["rails-app"], "brakeman-json", true, false, "Rails-aware SAST scanner.", "brakeman", "7.1.0"),
  item("flawfinder", "Flawfinder", "sast", "python", ["c", "cpp"], ["source"], "flawfinder-sarif", true, false, "Fast lexical C/C++ security scan with CWE-compatible output.", "flawfinder", "2.0.19"),
  item("cppcheck", "Cppcheck", "sast", "system", ["c", "cpp"], ["source"], "cppcheck-text", true, false, "Static C/C++ analyzer. HermSec runs it without compiling.", "cppcheck", "2.16.0"),
  item("dotnet-vulnerable", ".NET vulnerable packages", "sca", "system", ["csharp"], ["csproj", "sln", "packages.lock.json"], "dotnet-json", true, false, "Uses dotnet package listing for vulnerable NuGet packages.", "dotnet"),
];

const INSTALL_TIMEOUT_MS = 180_000;

export function defaultScannerSettings(): ScannerSettings {
  return {
    autoInstallMissing: true,
    allowOnlineUpdates: true,
    labInstallAll: false,
    items: scannerCatalog.map((scanner) => ({
      id: scanner.id,
      enabled: scanner.defaultEnabled,
      autoInstall: scanner.autoInstall,
    })),
  };
}

export function normalizeScannerSettings(settings?: Partial<ScannerSettings>): ScannerSettings {
  const defaults = defaultScannerSettings();
  const byId = new Map((settings?.items ?? []).map((entry) => [entry.id, entry]));
  return {
    autoInstallMissing: Boolean(settings?.autoInstallMissing ?? defaults.autoInstallMissing),
    allowOnlineUpdates: Boolean(settings?.allowOnlineUpdates ?? defaults.allowOnlineUpdates),
    labInstallAll: Boolean(settings?.labInstallAll ?? defaults.labInstallAll),
    items: scannerCatalog.map((scanner) => {
      const current = byId.get(scanner.id);
      return {
        id: scanner.id,
        enabled: current?.enabled ?? scanner.defaultEnabled,
        autoInstall: current?.autoInstall ?? scanner.autoInstall,
      };
    }),
  };
}

export function scannerStatuses(request: ScannerListRequest = {}): ScannerStatusItem[] {
  const settings = normalizeScannerSettings(readSettings().scanners);
  const profile = request.projectPath ? inspectProjectQuick(request.projectPath) : undefined;
  const configured = new Map(settings.items.map((entry) => [entry.id, entry]));
  return scannerCatalog.map((scanner) => {
    const user = configured.get(scanner.id);
    const enabled = Boolean(user?.enabled);
    const status = scannerStatus(scanner);
    return {
      ...scanner,
      enabled,
      autoInstallSelected: Boolean(user?.autoInstall),
      ...status,
      usedByCurrentProject: request.labProfile || settings.labInstallAll || !profile ? undefined : scannerMatchesProfile(scanner, profile),
    };
  });
}

export async function installScanner(scannerId: string): Promise<ScannerActionResult> {
  const scanner = scannerCatalog.find((item) => item.id === scannerId);
  if (!scanner) return { ok: false, scannerId, message: "Unknown scanner." };
  if (scanner.installKind === "built-in") {
    return { ok: true, scannerId, message: "Built-in scanner is already ready.", status: scannerStatuses().find((item) => item.id === scannerId) };
  }
  const plan = installPlan(scanner);
  if (!plan) {
    return {
      ok: false,
      scannerId,
      message: `${scanner.label} requires an external runtime or manual installation. HermSec will use it automatically when it is on PATH.`,
      status: scannerStatuses().find((item) => item.id === scannerId),
    };
  }
  mkdirSync(managedBinDir(), { recursive: true });
  try {
    await runInstall(plan.command, plan.args, plan.env);
    return {
      ok: true,
      scannerId,
      message: `${scanner.label} installed into HermSec managed tools.`,
      status: scannerStatuses().find((item) => item.id === scannerId),
    };
  } catch (error) {
    return {
      ok: false,
      scannerId,
      message: `${scanner.label} install failed: ${error instanceof Error ? error.message : String(error)}`,
      status: scannerStatuses().find((item) => item.id === scannerId),
    };
  }
}

export function uninstallScanner(scannerId: string): ScannerActionResult {
  const scanner = scannerCatalog.find((item) => item.id === scannerId);
  if (!scanner) return { ok: false, scannerId, message: "Unknown scanner." };
  const target = scannerManagedRoot(scanner);
  if (target && existsSync(target)) {
    rmSync(target, { recursive: true, force: true });
  }
  const exe = scanner.command ? managedExecutable(scanner.command) : undefined;
  if (exe && existsSync(exe)) {
    rmSync(exe, { force: true });
  }
  return {
    ok: true,
    scannerId,
    message: `${scanner.label} removed from HermSec managed tools when present. System installs are untouched.`,
    status: scannerStatuses().find((item) => item.id === scannerId),
  };
}

export async function updateScanner(scannerId: string): Promise<ScannerActionResult> {
  uninstallScanner(scannerId);
  return installScanner(scannerId);
}

export function scannerEnvForCli(projectPath?: string): Record<string, string> {
  const settings = normalizeScannerSettings(readSettings().scanners);
  const statuses = scannerStatuses({ projectPath, labProfile: settings.labInstallAll });
  const enabled = statuses
    .filter((scanner) => scanner.enabled && (settings.labInstallAll || scanner.usedByCurrentProject !== false))
    .map((scanner) => scanner.id);
  const env: Record<string, string> = {
    HERMSEC_ENABLED_SCANNERS: settings.labInstallAll ? "all" : enabled.length > 0 ? enabled.join(",") : "__none__",
    HERMSEC_SCANNER_AUTO_INSTALL: settings.autoInstallMissing ? "true" : "false",
    HERMSEC_SCANNER_ONLINE_UPDATES: settings.allowOnlineUpdates ? "true" : "false",
  };
  for (const scanner of statuses) {
    if (scanner.command && scanner.managedPath) {
      env[`HERMSEC_${scanner.command.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_BIN`] = scanner.managedPath;
    }
  }
  return env;
}

export async function prepareScannersForProject(projectPath: string): Promise<ScannerStatusItem[]> {
  const settings = normalizeScannerSettings(readSettings().scanners);
  let statuses = scannerStatuses({ projectPath, labProfile: settings.labInstallAll });
  if (!settings.autoInstallMissing) {
    return statuses;
  }

  const failures = new Map<string, string>();
  for (const scanner of statuses) {
    if (!scanner.enabled || (!settings.labInstallAll && scanner.usedByCurrentProject === false)) continue;
    if (!scanner.autoInstallSelected || scanner.status !== "missing") continue;
    const result = await installScanner(scanner.id);
    if (!result.ok) {
      failures.set(scanner.id, result.message);
    }
  }

  statuses = scannerStatuses({ projectPath, labProfile: settings.labInstallAll });
  if (failures.size === 0) {
    return statuses;
  }
  return statuses.map((scanner) => {
    const failure = failures.get(scanner.id);
    if (!failure || scanner.status !== "missing") return scanner;
    return { ...scanner, status: "failed", message: failure };
  });
}

export function updateScannerSettings(partial: Partial<ScannerSettings>): void {
  const current = normalizeScannerSettings(readSettings().scanners);
  updateSettings({ scanners: normalizeScannerSettings({ ...current, ...partial }) });
}

function item(
  id: string,
  label: string,
  category: ScannerCatalogItem["category"],
  installKind: ScannerCatalogItem["installKind"],
  languages: string[],
  inputs: string[],
  parser: string,
  defaultEnabled: boolean,
  autoInstall: boolean,
  riskNotes: string,
  command?: string,
  version?: string,
): ScannerCatalogItem {
  return { id, label, category, installKind, languages, inputs, parser, defaultEnabled, autoInstall, riskNotes, ...(command ? { command } : {}), ...(version ? { version } : {}) };
}

function scannerStatus(scanner: ScannerCatalogItem): Pick<ScannerStatusItem, "status" | "managedPath" | "systemPath" | "message"> {
  if (scanner.installKind === "built-in") {
    return { status: "built-in", message: "Built into HermSec." };
  }
  if (!scanner.command) {
    return { status: "missing", message: "No executable configured." };
  }
  const managedPath = managedExecutable(scanner.command);
  if (managedPath && existsSync(managedPath)) {
    return { status: "installed", managedPath, message: `Managed executable at ${managedPath}.` };
  }
  const systemPath = executableOnPath(scanner.command);
  if (systemPath) {
    return { status: "installed", systemPath, message: `Found on PATH at ${systemPath}.` };
  }
  return { status: "missing", message: `${scanner.command} is not installed yet.` };
}

function installPlan(scanner: ScannerCatalogItem): { command: string; args: string[]; env?: Record<string, string> } | undefined {
  const bin = managedBinDir();
  if (scanner.installKind === "python" && scanner.command && scanner.version) {
    const uv = executableOnPath("uv");
    if (!uv) return undefined;
    return {
      command: uv,
      args: ["tool", "install", "--force", `${scanner.command}==${scanner.version}`],
      env: {
        UV_TOOL_DIR: path.join(managedToolsRoot(), "python"),
        UV_TOOL_BIN_DIR: bin,
      },
    };
  }
  if (scanner.installKind === "npm" && scanner.command && scanner.version) {
    const npm = executableOnPath("npm");
    if (!npm) return undefined;
    return {
      command: npm,
      args: ["install", "--global", "--prefix", path.join(managedToolsRoot(), "node"), `${scanner.command}@${scanner.version}`, "--ignore-scripts"],
    };
  }
  if (scanner.installKind === "go" && scanner.command && scanner.version) {
    const go = executableOnPath("go");
    if (!go) return undefined;
    const module = scanner.id === "gosec"
      ? `github.com/securego/gosec/v2/cmd/gosec@${scanner.version}`
      : scanner.id === "govulncheck"
        ? `golang.org/x/vuln/cmd/govulncheck@${scanner.version}`
        : scanner.id === "trufflehog"
          ? `github.com/trufflesecurity/trufflehog/v3@${scanner.version}`
          : undefined;
    if (!module) return undefined;
    return { command: go, args: ["install", module], env: { GOBIN: bin } };
  }
  return undefined;
}

function runInstall(command: string, args: string[], extraEnv?: Record<string, string>): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: app.getPath("userData"),
      env: { ...process.env, ...extraEnv },
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`Install timed out after ${INSTALL_TIMEOUT_MS / 1000}s.`));
    }, INSTALL_TIMEOUT_MS);
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${String(chunk)}`.slice(-4000);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `${command} exited with code ${code ?? "unknown"}.`));
    });
  });
}

function inspectProjectQuick(projectPath: string): { languages: Set<string>; inputs: Set<string> } {
  const languages = new Set<string>();
  const inputs = new Set<string>();
  try {
    const stack = [projectPath];
    let seen = 0;
    while (stack.length > 0 && seen < 2500) {
      const current = stack.pop();
      if (!current) continue;
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        if ([".git", "node_modules", "dist", "build", ".hermsec", ".next", "vendor"].includes(entry.name)) continue;
        const full = path.join(current, entry.name);
        if (entry.isDirectory()) {
          stack.push(full);
          continue;
        }
        seen += 1;
        const ext = path.extname(entry.name).toLowerCase();
        const base = path.basename(entry.name);
        const lang = languageFor(ext, base);
        if (lang) languages.add(lang);
        if (isLockOrManifest(base, ext)) inputs.add(base);
        if (ext === ".tf" || base === "Dockerfile" || full.includes(".github\\workflows") || full.includes(".github/workflows")) inputs.add("iac");
      }
    }
  } catch {
    // Scanner filtering is advisory; scan execution remains authoritative.
  }
  return { languages, inputs };
}

function scannerMatchesProfile(scanner: ScannerCatalogItem, profile: { languages: Set<string>; inputs: Set<string> }): boolean {
  if (scanner.id === "hermsec-heuristics" || scanner.languages.includes("all")) return true;
  return scanner.languages.some((language) => profile.languages.has(language)) ||
    scanner.inputs.some((input) => profile.inputs.has(input));
}

function languageFor(ext: string, base: string): string | undefined {
  if (base === "Dockerfile") return "dockerfile";
  if (base.endsWith(".gradle.kts")) return "java";
  switch (ext) {
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".ts":
    case ".tsx":
      return "typescript";
    case ".py":
      return "python";
    case ".java":
    case ".jsp":
      return "java";
    case ".php":
      return "php";
    case ".go":
      return "go";
    case ".rs":
      return "rust";
    case ".rb":
      return "ruby";
    case ".c":
    case ".h":
      return "c";
    case ".cc":
    case ".cpp":
    case ".cxx":
    case ".hpp":
      return "cpp";
    case ".cs":
      return "csharp";
    case ".kt":
    case ".kts":
      return "kotlin";
    case ".html":
    case ".htm":
      return "html";
    case ".tf":
    case ".tfvars":
      return "terraform";
    case ".yml":
    case ".yaml":
      return "yaml";
    default:
      return undefined;
  }
}

function isLockOrManifest(base: string, ext: string): boolean {
  return [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "packages.lock.json",
  ].includes(base) || ext === ".csproj" || ext === ".sln";
}

function managedToolsRoot(): string {
  return path.join(app.getPath("userData"), "managed-scanners", `${process.platform}-${process.arch}`);
}

function managedBinDir(): string {
  const bin = path.join(managedToolsRoot(), "bin");
  mkdirSync(bin, { recursive: true });
  return bin;
}

function scannerManagedRoot(scanner: ScannerCatalogItem): string | undefined {
  if (scanner.installKind === "python") return path.join(managedToolsRoot(), "python", scanner.command ?? scanner.id);
  if (scanner.installKind === "npm") return path.join(managedToolsRoot(), "node");
  return undefined;
}

function managedExecutable(command: string): string | undefined {
  const suffixes = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  for (const suffix of suffixes) {
    const candidate = path.join(managedBinDir(), `${command}${suffix}`);
    if (existsSync(candidate)) return candidate;
  }
  const nodeCandidate = path.join(managedToolsRoot(), "node", process.platform === "win32" ? `${command}.cmd` : "bin/" + command);
  if (existsSync(nodeCandidate)) return nodeCandidate;
  return undefined;
}

function executableOnPath(command: string): string | undefined {
  const suffixes = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat", ".com"] : [""];
  for (const entry of (process.env.PATH ?? "").split(path.delimiter).filter(Boolean)) {
    for (const suffix of suffixes) {
      const candidate = path.join(entry, `${command}${suffix}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}
