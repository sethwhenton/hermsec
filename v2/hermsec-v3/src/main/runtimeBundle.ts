import { app } from "electron";
import { existsSync } from "node:fs";
import path from "node:path";

const mainDir = import.meta.dirname;
const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");
const scannerCommands = ["semgrep", "gitleaks", "bandit", "osv-scanner", "pip-audit", "pmg"] as const;

type ScannerCommand = (typeof scannerCommands)[number];

export function configureBundledRuntime(): void {
  const toolsRoot = findBundledToolsRoot();
  if (toolsRoot) {
    prependPath(toolPathEntries(toolsRoot));
    prependPathEnv("HERMSEC_TOOLS_DIR", [toolsRoot]);
    process.env.HERMSEC_BUNDLED_TOOLS_DIR = toolsRoot;
    for (const command of scannerCommands) {
      const executable = findBundledToolExecutable(toolsRoot, command);
      if (executable && !process.env[scannerOverrideEnvName(command)]) {
        process.env[scannerOverrideEnvName(command)] = executable;
      }
    }
  }

  const cliRoot = findBundledCliRoot();
  if (app.isPackaged && cliRoot && !process.env.HERMSEC_CLI_ROOT) {
    process.env.HERMSEC_CLI_ROOT = cliRoot;
  }

  process.env.NO_COLOR ??= "1";
  process.env.SEMGREP_SEND_METRICS ??= "off";
  process.env.SEMGREP_ENABLE_VERSION_CHECK ??= "0";
  process.env.PMG_DISABLE_TELEMETRY ??= "true";
}

export function findBundledCliRoot(): string | undefined {
  const configured = process.env.HERMSEC_CLI_ROOT?.trim();
  if (configured && hasHermsecCli(configured)) {
    return path.resolve(configured);
  }

  if (!app.isPackaged) {
    return undefined;
  }

  return cliRootCandidates().find(hasHermsecCli);
}

export function findBundledToolsRoot(): string | undefined {
  const configured = process.env.HERMSEC_BUNDLED_TOOLS_DIR?.trim();
  if (configured && existsSync(configured)) {
    return path.resolve(configured);
  }

  return toolRootCandidates().find((candidate) => existsSync(candidate));
}

function cliRootCandidates(): string[] {
  return unique([
    path.join(process.resourcesPath, "hermsec-cli"),
    path.resolve(mainDir, "../../resources/hermsec-cli"),
    path.resolve(process.cwd(), "resources/hermsec-cli"),
  ]);
}

function toolRootCandidates(): string[] {
  const platformKey = `${process.platform}-${process.arch}`;
  return unique([
    path.join(process.resourcesPath, "runtime-tools", platformKey),
    path.resolve(mainDir, "../../resources/runtime-tools", platformKey),
    path.resolve(process.cwd(), "resources/runtime-tools", platformKey),
  ]);
}

function hasHermsecCli(root: string): boolean {
  return existsSync(path.join(root, CLI_RELATIVE_PATH));
}

function toolPathEntries(toolsRoot: string): string[] {
  return [
    path.join(toolsRoot, "bin"),
    ...scannerCommands.flatMap((command) => [
      path.join(toolsRoot, "python", command, process.platform === "win32" ? "Scripts" : "bin"),
    ]),
  ].filter((entry) => existsSync(entry));
}

function findBundledToolExecutable(toolsRoot: string, command: ScannerCommand): string | undefined {
  const suffixes = executableSuffixes(command);
  const directories = [
    path.join(toolsRoot, "bin"),
    path.join(toolsRoot, "python", command, process.platform === "win32" ? "Scripts" : "bin"),
  ];

  for (const directory of directories) {
    for (const suffix of suffixes) {
      const candidate = path.join(directory, `${command}${suffix}`);
      if (existsSync(candidate)) {
        return candidate;
      }
    }
  }

  return undefined;
}

function executableSuffixes(command: string): string[] {
  if (path.extname(command) || process.platform !== "win32") {
    return [""];
  }
  return ["", ".exe", ".cmd", ".bat", ".com"];
}

function scannerOverrideEnvName(command: ScannerCommand): string {
  return `HERMSEC_${command.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_BIN`;
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
