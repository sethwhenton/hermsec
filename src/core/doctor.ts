import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import type { ScannerStatus } from "../shared/types.js";

type ToolProbe = {
  id: string;
  label: string;
  executable: string;
};

const TOOL_PROBES: ToolProbe[] = [
  { id: "git", label: "Git", executable: "git" },
  { id: "npm-audit", label: "npm audit", executable: "npm" },
  { id: "semgrep", label: "Semgrep", executable: "semgrep" },
  { id: "gitleaks", label: "Gitleaks", executable: "gitleaks" },
  { id: "bandit", label: "Bandit", executable: "bandit" },
  { id: "pip-audit", label: "pip-audit", executable: "pip-audit" },
  { id: "osv-scanner", label: "OSV-Scanner", executable: "osv-scanner" },
];

export function scannerAvailabilityStatuses(): ScannerStatus[] {
  return TOOL_PROBES.map((tool) => {
    const resolved = findExecutableOnPath(tool.executable);
    if (resolved) {
      return {
        id: tool.id,
        label: tool.label,
        status: "ready",
        message: `${tool.label} was detected on PATH. The local harness does not require it for offline scans.`,
      };
    }
    return {
      id: tool.id,
      label: tool.label,
      status: "missing",
      message: `${tool.label} was not detected on PATH. Built-in offline heuristics remain available.`,
    };
  });
}

export async function runDoctor(): Promise<{
  node: string;
  platform: string;
  scanners: ScannerStatus[];
}> {
  return {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    scanners: scannerAvailabilityStatuses(),
  };
}

export function findExecutableOnPath(command: string): string | undefined {
  const pathValue = process.env.PATH;
  if (!pathValue) {
    return undefined;
  }

  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) {
      continue;
    }
    for (const suffix of executableSuffixes(command)) {
      const candidate = path.join(directory, `${command}${suffix}`);
      if (isFile(candidate)) {
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
  const pathExt = process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD";
  return ["", ...pathExt.split(";").filter(Boolean).map((item) => item.toLowerCase())];
}

function isFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}
