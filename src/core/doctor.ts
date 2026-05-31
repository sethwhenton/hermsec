import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { externalScannerCatalog } from "../scanners/external.js";
import type { ScannerStatus } from "../shared/types.js";

type ToolProbe = {
  id: string;
  label: string;
  executable: string;
  requirement: "required" | "recommended" | "optional";
};

const TOOL_PROBES: ToolProbe[] = [
  { id: "git", label: "Git", executable: "git", requirement: "required" },
  ...externalScannerCatalog().map((scanner) => ({
    id: scanner.id,
    label: scanner.label,
    executable: scanner.executable,
    requirement: scanner.id === "pmg" ? "recommended" as const : "optional" as const,
  })),
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
      status: tool.requirement === "required" ? "missing" : "skipped",
      message: tool.requirement === "required"
        ? `${tool.label} was not detected on PATH. This is required for production readiness.`
        : `${tool.label} was not detected on PATH. This optional tool was skipped; built-in offline heuristics remain available.`,
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
