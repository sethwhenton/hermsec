import { BrowserWindow } from "electron";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { buildDashboardReport } from "./reportData";
import type { ProjectStateFingerprint } from "./projectState";
import { SCAN_METADATA_FILE, type LocalScanMetadata } from "./scanMetadata";

export interface ReportArtifactResult {
  reportDir: string;
  dashboardHtmlPath: string;
  onepagerHtmlPath: string;
  onepagerPdfPath?: string;
  projectStatePath: string;
  scanMetadataPath: string;
}

export interface DashboardBundleResult {
  ok: boolean;
  html?: string;
  reportDir?: string;
  dashboardHtmlPath?: string;
  onepagerHtmlPath?: string;
  onepagerPdfPath?: string;
  message?: string;
  error?: string;
}

const templateFiles = [
  "styles-v4.css",
  "app-v4.js",
  "styles-onepager.css",
  "app-onepager.js",
] as const;

export async function generateReportArtifacts(
  reportDir: string,
  projectState?: ProjectStateFingerprint,
  scanMetadata?: LocalScanMetadata,
): Promise<ReportArtifactResult> {
  const normalizedReportDir = path.resolve(reportDir);
  const dashboardDir = path.join(normalizedReportDir, "dashboard");
  const onepagerDir = path.join(normalizedReportDir, "onepager");
  mkdirSync(dashboardDir, { recursive: true });
  mkdirSync(onepagerDir, { recursive: true });

  const templates = readTemplates();
  for (const name of templateFiles) {
    const targetDir = name.includes("onepager") ? onepagerDir : dashboardDir;
    writeFileSync(path.join(targetDir, name), templates[name], "utf8");
  }

  const projectStatePath = path.join(normalizedReportDir, "project-state.json");
  const scanMetadataPath = path.join(normalizedReportDir, SCAN_METADATA_FILE);
  if (projectState) {
    writeFileSync(projectStatePath, JSON.stringify(projectState, null, 2), "utf8");
  }
  if (scanMetadata) {
    writeFileSync(scanMetadataPath, JSON.stringify(scanMetadata, null, 2), "utf8");
  }

  const report = buildDashboardReport(normalizedReportDir);
  const dataJson = JSON.stringify(report, null, 2).replace(/</g, "\\u003c");
  const data = `const HERMSEC_REPORT = ${dataJson};\nwindow.HERMSEC_REPORT = HERMSEC_REPORT;\n`;
  writeFileSync(path.join(dashboardDir, "data.js"), data, "utf8");
  writeFileSync(path.join(onepagerDir, "data.js"), data, "utf8");

  const dashboardHtmlPath = path.join(dashboardDir, "index.html");
  const onepagerHtmlPath = path.join(onepagerDir, "index.html");
  writeFileSync(dashboardHtmlPath, dashboardHtml(), "utf8");
  writeFileSync(onepagerHtmlPath, onepagerHtml(), "utf8");

  const onepagerPdfPath = await generateOnepagerPdf(onepagerHtmlPath);
  return {
    reportDir: normalizedReportDir,
    dashboardHtmlPath,
    onepagerHtmlPath,
    ...(onepagerPdfPath ? { onepagerPdfPath } : {}),
    projectStatePath,
    scanMetadataPath,
  };
}

export function dashboardBundle(reportPathOrDir: string): DashboardBundleResult {
  try {
    const reportDir = resolveReportDir(reportPathOrDir);
    const dashboardDir = path.join(reportDir, "dashboard");
    const onepagerDir = path.join(reportDir, "onepager");
    const dashboardHtmlPath = path.join(dashboardDir, "index.html");
    const onepagerHtmlPath = path.join(onepagerDir, "index.html");
    const onepagerPdfPath = path.join(onepagerDir, "report.pdf");

    if (!existsSync(dashboardHtmlPath)) {
      return {
        ok: false,
        reportDir,
        message: `Dashboard report was not found: ${dashboardHtmlPath}`,
      };
    }

    let html = readFileSync(dashboardHtmlPath, "utf8");
    const templates = readTemplates();
    html = html.replace(
      /<link rel="stylesheet" href="styles-v4\.css">\s*/u,
      `<style>${templates["styles-v4.css"]}\n${hermsecDashboardThemeCss()}</style>\n`,
    );
    const report = buildDashboardReport(reportDir);
    const dataJson = JSON.stringify(report, null, 2).replace(/</g, "\\u003c");
    html = html.replace(
      /<script src="data\.js"><\/script>/u,
      `<script>const HERMSEC_REPORT = ${dataJson};\nwindow.HERMSEC_REPORT = HERMSEC_REPORT;</script>`,
    );
    html = html.replace(
      /<script src="app-v4\.js"><\/script>/u,
      `<script>${templates["app-v4.js"]}</script>`,
    );
    html = html.replace(/<html lang="en"(?: data-theme="[^"]+")?>/u, '<html lang="en" data-theme="dark">');

    return {
      ok: true,
      html,
      reportDir,
      dashboardHtmlPath,
      ...(existsSync(onepagerHtmlPath) ? { onepagerHtmlPath } : {}),
      ...(existsSync(onepagerPdfPath) ? { onepagerPdfPath } : {}),
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not build dashboard bundle.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function readTemplates(): Record<(typeof templateFiles)[number], string> {
  const dir = templateDir();
  return Object.fromEntries(
    templateFiles.map((name) => [name, readFileSync(path.join(dir, name), "utf8")]),
  ) as Record<(typeof templateFiles)[number], string>;
}

function templateDir(): string {
  const candidates = [
    path.join(import.meta.dirname, "reportTemplates"),
    path.resolve(process.cwd(), "src", "main", "reportTemplates"),
    path.resolve(process.cwd(), "v2", "hermsec-v3", "src", "main", "reportTemplates"),
  ];

  const found = candidates.find((candidate) => templateFiles.every((name) => existsSync(path.join(candidate, name))));
  if (!found) {
    throw new Error("Hermsec report templates were not found.");
  }
  return found;
}

function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hermsec Security Report</title>
  <link rel="stylesheet" href="styles-v4.css">
</head>
<body>
  <div class="page-backdrop" aria-hidden="true">
    <div class="page-grid"></div>
    <div class="page-glow page-glow--cool"></div>
    <div class="page-glow page-glow--warm"></div>
  </div>
  <div class="grain" aria-hidden="true"></div>
  <div class="report" id="report">
    <header class="report-header" id="report-header"></header>
    <nav class="tab-nav" id="tab-nav" aria-label="Report sections">
      <div class="tab-nav-shell">
        <div class="tab-nav-inner" id="tab-nav-inner">
          <div class="tab-indicator" id="tab-indicator" aria-hidden="true"></div>
        </div>
      </div>
    </nav>
    <main class="report-main" id="report-main">
      <section class="tab-panel active" id="panel-pipeline" aria-labelledby="tab-pipeline"></section>
      <section class="tab-panel" id="panel-findings" aria-labelledby="tab-findings"></section>
      <section class="tab-panel" id="panel-adjudication" aria-labelledby="tab-adjudication"></section>
      <section class="tab-panel" id="panel-threat" aria-labelledby="tab-threat"></section>
      <section class="tab-panel" id="panel-intel" aria-labelledby="tab-intel"></section>
      <section class="tab-panel" id="panel-fixplan" aria-labelledby="tab-fixplan"></section>
      <section class="tab-panel" id="panel-appendix" aria-labelledby="tab-appendix"></section>
    </main>
    <footer class="report-footer" id="report-footer"></footer>
  </div>
  <div class="toast" id="toast" role="status" aria-live="polite"></div>
  <script src="data.js"></script>
  <script src="app-v4.js"></script>
</body>
</html>
`;
}

function onepagerHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hermsec Executive Report</title>
  <link rel="stylesheet" href="styles-onepager.css">
</head>
<body>
  <div class="screen-toolbar no-print" id="screen-toolbar"></div>
  <article class="onepager" id="onepager">
    <header class="op-cover" id="op-cover"></header>
    <section class="op-section" id="op-summary" aria-labelledby="op-summary-title"></section>
    <section class="op-section" id="op-pipeline" aria-labelledby="op-pipeline-title"></section>
    <section class="op-section" id="op-findings" aria-labelledby="op-findings-title"></section>
    <section class="op-section" id="op-fixplan" aria-labelledby="op-fixplan-title"></section>
    <section class="op-section" id="op-intel" aria-labelledby="op-intel-title"></section>
    <section class="op-section op-appendix" id="op-appendix" aria-labelledby="op-appendix-title"></section>
    <footer class="op-footer" id="op-footer"></footer>
  </article>
  <script src="data.js"></script>
  <script src="app-onepager.js"></script>
</body>
</html>
`;
}

function hermsecDashboardThemeCss(): string {
  return `
[data-theme="dark"] {
  --bg: #09090b;
  --surface: #111113;
  --surface-muted: #18181b;
  --border: rgba(244, 244, 245, 0.11);
  --border-subtle: rgba(244, 244, 245, 0.07);
  --text: #f4f4f5;
  --text-secondary: #d4d4d8;
  --text-muted: #71717a;
  --accent: #3b82f6;
  --accent-hover: #60a5fa;
  --accent-subtle: rgba(29, 78, 216, 0.18);
  --accent-crimson: #ef4444;
  --critical: #f87171;
  --critical-bg: rgba(239, 68, 68, 0.13);
  --high: #fb923c;
  --high-bg: rgba(251, 146, 60, 0.13);
  --medium: #facc15;
  --medium-bg: rgba(250, 204, 21, 0.12);
  --low: #a1a1aa;
  --low-bg: rgba(161, 161, 170, 0.12);
  --info: #93c5fd;
  --info-bg: rgba(59, 130, 246, 0.12);
  --success: #22c55e;
  --success-bg: rgba(34, 197, 94, 0.12);
  --warning: #facc15;
  --warning-bg: rgba(250, 204, 21, 0.12);
  --error: #ef4444;
  --error-bg: rgba(239, 68, 68, 0.13);
  --skipped: #71717a;
  --skipped-bg: rgba(113, 113, 122, 0.12);
  --bezel-bg: rgba(244, 244, 245, 0.04);
  --chip-bg: rgba(244, 244, 245, 0.06);
  --header-bg: rgba(9, 9, 11, 0.88);
  --tab-shell-bg: rgba(244, 244, 245, 0.04);
  --tab-inner-bg: rgba(17, 17, 19, 0.9);
  --hover-elevated: rgba(244, 244, 245, 0.08);
  --surface-highlight: rgba(244, 244, 245, 0.06);
  --evidence-inset: rgba(244, 244, 245, 0.035);
  --link-arrow-bg: rgba(59, 130, 246, 0.16);
  --agent-border: rgba(59, 130, 246, 0.24);
  --page-grid-color: rgba(244, 244, 245, 0.035);
  --page-glow-cool: radial-gradient(circle, rgba(59, 130, 246, 0.12) 0%, transparent 70%);
  --page-glow-warm: radial-gradient(circle, rgba(239, 68, 68, 0.08) 0%, transparent 70%);
}
`;
}

async function generateOnepagerPdf(onepagerHtmlPath: string): Promise<string | undefined> {
  const pdfPath = path.join(path.dirname(onepagerHtmlPath), "report.pdf");
  let win: BrowserWindow | null = null;
  try {
    win = new BrowserWindow({
      show: false,
      width: 1200,
      height: 1600,
      webPreferences: {
        offscreen: true,
        sandbox: false,
      },
    });
    await win.loadFile(onepagerHtmlPath);
    await win.webContents.executeJavaScript(
      "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))",
    );
    const pdf = await win.webContents.printToPDF({
      printBackground: true,
      preferCSSPageSize: true,
      pageSize: "A4",
    });
    writeFileSync(pdfPath, pdf);
    return pdfPath;
  } catch {
    return undefined;
  } finally {
    win?.close();
  }
}

function resolveReportDir(reportPathOrDir: string): string {
  const resolved = path.resolve(reportPathOrDir);
  if (resolved.endsWith(".html") || resolved.endsWith(".json")) {
    return path.dirname(resolved);
  }
  if (path.basename(resolved).toLowerCase() === "dashboard" || path.basename(resolved).toLowerCase() === "onepager") {
    return path.dirname(resolved);
  }
  return resolved;
}
