import type { HermsecAutomation, HermsecProject, HermsecReportPreview, HermsecSettingsState } from "./types";

export const MOCK_AUTOMATIONS: HermsecAutomation[] = [
  {
    id: "auto-1",
    name: "Nightly dependency audit",
    schedule: "Daily · 02:00",
    targetProject: "payments-api",
    nextRun: "Tonight 02:00",
    lastResult: "success",
    reportFolder: "reports/payments-api/nightly",
    enabled: true,
  },
  {
    id: "auto-2",
    name: "Weekly SAST sweep",
    schedule: "Mon · 06:30",
    targetProject: "hermsec-v2",
    nextRun: "Mon 06:30",
    lastResult: "success",
    reportFolder: "reports/hermsec-v2/sast",
    enabled: true,
  },
  {
    id: "auto-3",
    name: "Pre-release secret scan",
    schedule: "On demand",
    targetProject: "mobile-gateway",
    nextRun: "—",
    lastResult: "failed",
    reportFolder: "reports/mobile-gateway/secrets",
    enabled: false,
  },
  {
    id: "auto-4",
    name: "Container image CVE check",
    schedule: "Wed · 18:00",
    targetProject: "infra-images",
    nextRun: "Wed 18:00",
    lastResult: "running",
    reportFolder: "reports/infra-images/cve",
    enabled: true,
  },
];

export const MOCK_PROJECTS: HermsecProject[] = [
  {
    id: "proj-1",
    name: "payments-api",
    path: "E:/Projects/payments-api",
    lastScan: "2 hours ago",
    findingCount: 3,
    riskLevel: "medium",
  },
  {
    id: "proj-2",
    name: "hermsec-v2",
    path: "E:/Programming/Security insider II/Hermsec Proj/v2",
    lastScan: "Yesterday",
    findingCount: 0,
    riskLevel: "low",
  },
  {
    id: "proj-3",
    name: "mobile-gateway",
    path: "E:/Projects/mobile-gateway",
    lastScan: "4 days ago",
    findingCount: 11,
    riskLevel: "high",
  },
];

const SAMPLE_REPORT_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Hermsec Scan Report</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: #0f1115;
      color: #e8eaed;
      line-height: 1.5;
    }
    header {
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid #2a2f38;
      background: #12151a;
    }
    h1 { margin: 0 0 0.25rem; font-size: 1.1rem; font-weight: 600; }
    .meta { color: #9aa0a6; font-size: 0.8rem; }
    main { padding: 1.25rem 1.5rem; }
    .summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.25rem;
    }
    .card {
      border: 1px solid #2a2f38;
      border-radius: 0.5rem;
      padding: 0.75rem 1rem;
      background: #151922;
    }
    .card strong { display: block; font-size: 1.25rem; margin-bottom: 0.15rem; }
    .card span { color: #9aa0a6; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 0.55rem 0.65rem; border-bottom: 1px solid #232833; }
    th { color: #9aa0a6; font-weight: 500; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .sev-high { color: #f87171; }
    .sev-medium { color: #fbbf24; }
    .sev-low { color: #86efac; }
  </style>
</head>
<body>
  <header>
    <h1>Hermsec Security Report</h1>
    <div class="meta">payments-api · offline scan · 2026-06-05 02:14 UTC</div>
  </header>
  <main>
    <div class="summary">
      <div class="card"><strong>3</strong><span>Findings</span></div>
      <div class="card"><strong>1</strong><span>High</span></div>
      <div class="card"><strong>47s</strong><span>Duration</span></div>
    </div>
    <table>
      <thead>
        <tr><th>Severity</th><th>Rule</th><th>Location</th></tr>
      </thead>
      <tbody>
        <tr>
          <td class="sev-high">High</td>
          <td>Hardcoded credential pattern</td>
          <td>src/config/stripe.ts:18</td>
        </tr>
        <tr>
          <td class="sev-medium">Medium</td>
          <td>Outdated dependency (axios)</td>
          <td>package.json</td>
        </tr>
        <tr>
          <td class="sev-low">Low</td>
          <td>Missing security header</td>
          <td>src/server.ts:42</td>
        </tr>
      </tbody>
    </table>
  </main>
</body>
</html>`;

export const MOCK_REPORTS: HermsecReportPreview[] = [
  {
    id: "report-1",
    title: "payments-api nightly",
    path: "reports/payments-api/nightly/index.html",
    html: SAMPLE_REPORT_HTML,
  },
  {
    id: "report-2",
    title: "hermsec-v2 sast",
    path: "reports/hermsec-v2/sast/index.html",
    html: SAMPLE_REPORT_HTML.replace("payments-api", "hermsec-v2"),
  },
];

export const DEFAULT_HERMSEC_SETTINGS: HermsecSettingsState = {
  provider: "opencode-go",
  model: "deepseek-v4-flash",
  apiKeyEnvVar: "OPENCODE_GO_API_KEY",
  baseUrl: "",
  defaultReportDirectory: "~/Hermsec/reports",
  privacyMode: true,
  scanMode: "auto",
  automationDefaultSchedule: "Daily · 02:00",
};
