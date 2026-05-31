import fs from "node:fs/promises";
import path from "node:path";
import type { CommandResult } from "../shared/types.js";
import { defaultReportDir } from "../shared/paths.js";
import { findReportIndexEntry, listReportIndexEntries } from "./reportIndex.js";

export type ResolvedReportDestination = {
  configuredReportDir?: string;
  actualReportRoot: string;
  fallbackUsed: boolean;
  fallbackReason?: string;
};

export async function resolveReportDestination(configuredReportDir?: string): Promise<ResolvedReportDestination> {
  if (configuredReportDir) {
    const check = await canWriteDirectory(configuredReportDir);
    if (check.ok) {
      return {
        configuredReportDir,
        actualReportRoot: path.resolve(configuredReportDir),
        fallbackUsed: false
      };
    }
    return {
      configuredReportDir,
      actualReportRoot: await ensureFallbackDir(),
      fallbackUsed: true,
      fallbackReason: check.reason
    };
  }

  return {
    actualReportRoot: await ensureFallbackDir(),
    fallbackUsed: false
  };
}

async function ensureFallbackDir(): Promise<string> {
  const fallback = defaultReportDir();
  await fs.mkdir(fallback, { recursive: true });
  return path.resolve(fallback);
}

async function canWriteDirectory(dir: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  try {
    const resolved = path.resolve(dir);
    await fs.mkdir(resolved, { recursive: true });
    const probe = path.join(resolved, `.hermsec-write-${process.pid}-${Date.now()}.tmp`);
    await fs.writeFile(probe, "ok", "utf8");
    await fs.unlink(probe);
    return { ok: true };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { ok: false, reason };
  }
}

export async function listReports(options: { cwd: string; workspaceId?: string }): Promise<CommandResult> {
  const reports = await listReportIndexEntries(options.workspaceId ? { workspaceId: options.workspaceId } : {});
  return {
    ok: true,
    message: reports.length
      ? reports.map((report) => `${report.scanId}\t${report.generatedAt}\t${report.htmlPath}`).join("\n")
      : "No reports found.",
    data: { reports },
  };
}

export async function openReport(options: { cwd: string; selector: string }): Promise<CommandResult> {
  const reports = await listReportIndexEntries();
  const report =
    options.selector === "latest"
      ? reports[0]
      : (await findReportIndexEntry(options.selector)) ??
        reports.find((entry) => entry.reportDir === path.resolve(options.cwd, options.selector));
  if (!report) {
    return {
      ok: false,
      errorCode: "REPORT_NOT_FOUND",
      message: `Report not found: ${options.selector}`,
      remediation: "Run `hermsec report list` to see saved reports.",
    };
  }
  return {
    ok: true,
    message: report.htmlPath,
    data: { path: report.htmlPath, report },
  };
}

export async function getReportPath(options: {
  cwd: string;
  workspaceId?: string;
  reportId?: string;
}): Promise<CommandResult<{ path: string }>> {
  if (options.reportId) {
    const report = await findReportIndexEntry(options.reportId);
    if (report) {
      return { ok: true, message: report.reportDir, data: { path: report.reportDir } };
    }
  }
  const reports = await listReportIndexEntries(options.workspaceId ? { workspaceId: options.workspaceId } : {});
  const latest = reports[0];
  return {
    ok: true,
    message: latest?.reportDir ?? defaultReportDir(),
    data: { path: latest?.reportDir ?? defaultReportDir() },
  };
}
