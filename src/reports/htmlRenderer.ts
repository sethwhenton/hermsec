import { displayScannerName } from "./displayNames.js";
import type { ReportDocument, ReportFinding } from "./schema.js";
import { compareFindings, severityOrder } from "./schema.js";

const template = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hermsec Security Report</title>
  <link rel="stylesheet" href="./report.css">
</head>
<body>
  <main class="report-shell">
    {{metadata}}
    {{summary}}
    <div class="report-layout">
      <div class="report-main">
        {{priorityActions}}
        {{intelligence}}
        {{findings}}
      </div>
      <aside class="report-sidebar" aria-label="Report context">
        {{delta}}
        {{agentMode}}
        {{scannerStatus}}
        {{evidenceBundle}}
        {{limitations}}
      </aside>
    </div>
  </main>
</body>
</html>`;

export const defaultReportCss = `:root {
  color-scheme: light;
  --bg: #f3f6f7;
  --panel: #ffffff;
  --panel-soft: #f8fbfa;
  --panel-strong: #102a33;
  --text: #172033;
  --muted: #617081;
  --subtle: #eef3f2;
  --border: #d6dee5;
  --border-strong: #bdc9d3;
  --accent: #0f766e;
  --accent-strong: #11505d;
  --critical: #9f1d2e;
  --critical-bg: #fff1f3;
  --high: #b45309;
  --high-bg: #fff7ed;
  --medium: #8a6a08;
  --medium-bg: #fffbe6;
  --low: #2f6f4e;
  --low-bg: #f0fdf4;
  --info: #2563a1;
  --info-bg: #eff6ff;
  --shadow: 0 18px 48px rgba(16, 42, 51, 0.08);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    linear-gradient(180deg, #e8f0f2 0, #f3f6f7 260px),
    var(--bg);
  color: var(--text);
}
.report-shell {
  max-width: 1180px;
  margin: 0 auto;
  padding: 34px 22px 54px;
}
.report-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
  gap: 24px;
  align-items: stretch;
  background: var(--panel-strong);
  color: #f8fbfa;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 8px;
  box-shadow: var(--shadow);
  margin: 0 0 18px;
  padding: 28px;
}
.hero-eyebrow {
  margin: 0 0 8px;
  color: #a7f3d0;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}
.report-hero h1 {
  margin: 0;
  max-width: 760px;
  font-size: clamp(2rem, 4vw, 3.25rem);
  line-height: 1.05;
}
.hero-lede {
  max-width: 760px;
  margin: 14px 0 0;
  color: #d8e6e8;
  font-size: 1.02rem;
}
.hero-flags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 20px;
}
.metadata-grid,
.finding-meta,
.key-values {
  display: grid;
  gap: 10px;
  margin: 0;
}
.metadata-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-content: start;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 8px;
  padding: 14px;
}
.metadata-item,
.detail-item {
  min-width: 0;
}
.metadata-item dt,
.detail-item dt,
.key-values dt {
  margin: 0 0 2px;
  color: var(--muted);
  font-size: 0.76rem;
  font-weight: 700;
  text-transform: uppercase;
}
.metadata-item dt {
  color: #b9cdd2;
}
.metadata-item dd,
.detail-item dd,
.key-values dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
.metadata-item code {
  color: #f8fbfa;
}
.section {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(16, 42, 51, 0.05);
  margin: 0 0 16px;
  padding: 20px;
}
.section-header {
  display: flex;
  gap: 14px;
  align-items: start;
  justify-content: space-between;
  margin: 0 0 14px;
}
.section-kicker {
  margin: 0 0 4px;
  color: var(--accent-strong);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
}
.report-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 340px;
  gap: 18px;
  align-items: start;
}
.report-main,
.report-sidebar {
  min-width: 0;
}
.report-sidebar {
  position: sticky;
  top: 16px;
}
h1, h2, h3, h4 { margin: 0 0 10px; line-height: 1.2; }
h2 { font-size: 1.28rem; }
h3 { font-size: 1rem; }
h4 { font-size: 0.9rem; }
p { margin: 0 0 10px; }
a { color: var(--accent-strong); }
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 10px;
  table-layout: fixed;
}
th, td {
  text-align: left;
  border-bottom: 1px solid var(--border);
  padding: 10px 8px;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
}
tbody tr:last-child td {
  border-bottom: 0;
}
code,
pre {
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  font-size: 0.95em;
}
code {
  overflow-wrap: anywhere;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.muted,
.empty-state {
  color: var(--muted);
}
.empty-state {
  margin: 0;
}
.summary-card {
  border: 0;
  box-shadow: var(--shadow);
}
.summary-topline {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 18px;
  align-items: end;
  margin-bottom: 16px;
}
.summary-status {
  max-width: 420px;
  color: var(--muted);
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(128px, 1fr));
  gap: 10px;
}
.metric {
  min-height: 104px;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  background: var(--panel-soft);
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
}
.metric strong {
  display: block;
  margin-top: 8px;
  font-size: 1.85rem;
  line-height: 1;
}
.metric small {
  display: block;
  margin-top: 8px;
  color: var(--muted);
}
.metric.critical { border-color: #efb2bc; background: var(--critical-bg); }
.metric.high { border-color: #f4c48c; background: var(--high-bg); }
.metric.medium { border-color: #eadf8f; background: var(--medium-bg); }
.metric.low { border-color: #b7dfc7; background: var(--low-bg); }
.metric.info { border-color: #b8d4f4; background: var(--info-bg); }
.metric.failure { border-color: #efb2bc; }
.badge,
.status-pill,
.id-pill {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 3px 9px;
  margin: 0 6px 6px 0;
  background: #fff;
  color: var(--text);
  font-size: 0.8rem;
  font-weight: 700;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.status-pill {
  background: rgba(255, 255, 255, 0.1);
  border-color: rgba(255, 255, 255, 0.18);
  color: #f8fbfa;
}
.status-pill.redaction-on,
.status-pill.completed,
.status-pill.ready {
  border-color: rgba(167, 243, 208, 0.45);
  color: #bbf7d0;
}
.status-pill.redaction-off,
.status-pill.skipped,
.status-pill.missing {
  border-color: rgba(250, 204, 21, 0.45);
  color: #fde68a;
}
.status-pill.failed {
  border-color: rgba(251, 113, 133, 0.5);
  color: #fecdd3;
}
.section .status-pill {
  background: var(--panel-soft);
  border-color: var(--border);
  color: var(--text);
}
.section .status-pill.completed,
.section .status-pill.ready {
  background: var(--low-bg);
  border-color: #b7dfc7;
  color: var(--low);
}
.section .status-pill.skipped,
.section .status-pill.missing {
  background: var(--medium-bg);
  border-color: #eadf8f;
  color: var(--medium);
}
.section .status-pill.failed {
  background: var(--critical-bg);
  border-color: #efb2bc;
  color: var(--critical);
}
.badge.critical,
.id-pill.critical { color: var(--critical); border-color: #efb2bc; background: var(--critical-bg); }
.badge.high,
.id-pill.high { color: var(--high); border-color: #f4c48c; background: var(--high-bg); }
.badge.medium,
.id-pill.medium { color: var(--medium); border-color: #eadf8f; background: var(--medium-bg); }
.badge.low,
.id-pill.low { color: var(--low); border-color: #b7dfc7; background: var(--low-bg); }
.badge.info,
.id-pill.info { color: var(--info); border-color: #b8d4f4; background: var(--info-bg); }
.badge.subtle {
  background: var(--subtle);
  color: var(--accent-strong);
}
.action-list {
  list-style: none;
  padding: 0;
  margin: 0;
  counter-reset: action;
}
.action-list li {
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr);
  gap: 12px;
  padding: 12px 0;
  border-top: 1px solid var(--border);
  counter-increment: action;
}
.action-list li:first-child {
  border-top: 0;
  padding-top: 0;
}
.action-list li::before {
  content: counter(action);
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: 999px;
  background: var(--panel-strong);
  color: #fff;
  font-weight: 800;
}
.action-title {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  margin-bottom: 4px;
}
.action-fix {
  margin: 0;
  color: var(--muted);
}
.severity-group {
  margin-top: 18px;
}
.severity-group:first-of-type {
  margin-top: 0;
}
.severity-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
  padding-bottom: 8px;
}
.finding {
  border: 1px solid var(--border);
  border-left: 5px solid var(--info);
  border-radius: 8px;
  margin: 0 0 14px;
  padding: 18px;
  background: #fff;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding-title-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: start;
}
.finding-title-row h3 {
  font-size: 1.08rem;
}
.badge-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0;
}
.finding-meta {
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel-soft);
  margin: 12px 0;
  padding: 12px;
}
.finding-content-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.finding-block {
  min-width: 0;
  border-top: 1px solid var(--border);
  padding-top: 12px;
}
.finding-block.full {
  grid-column: 1 / -1;
}
.finding-block p,
.finding-block ol {
  margin-bottom: 0;
}
.evidence-block {
  max-height: 260px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  margin: 0;
  padding: 12px;
  background: #0f172a;
  color: #e5edf6;
}
.delta-grid {
  display: grid;
  gap: 10px;
}
.delta-item {
  border-top: 1px solid var(--border);
  padding-top: 10px;
}
.delta-item:first-child {
  border-top: 0;
  padding-top: 0;
}
.id-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 4px;
}
.id-pill {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  font-weight: 600;
}
.compact-table {
  font-size: 0.88rem;
}
.compact-table th,
.compact-table td {
  padding: 8px 6px;
}
.duration {
  white-space: nowrap;
}
.limitations-list {
  margin: 0;
  padding-left: 18px;
}
@media (max-width: 940px) {
  .report-hero,
  .report-layout,
  .summary-topline {
    grid-template-columns: 1fr;
  }
  .report-sidebar {
    position: static;
  }
}
@media (max-width: 640px) {
  .report-shell {
    padding: 18px 12px 34px;
  }
  .report-hero,
  .section,
  .finding {
    padding: 16px;
  }
  .metadata-grid,
  .finding-content-grid {
    grid-template-columns: 1fr;
  }
  .finding-title-row {
    grid-template-columns: 1fr;
  }
  table {
    display: block;
    overflow-x: auto;
  }
}
@media print {
  body { background: #fff; }
  .report-shell { max-width: none; padding: 0; }
  .report-hero,
  .section,
  .finding {
    break-inside: avoid;
    box-shadow: none;
    border-color: #bbb;
  }
  .report-layout {
    display: block;
  }
  .report-sidebar {
    position: static;
  }
  .evidence-block {
    max-height: none;
  }
  a[href]::after { content: " (" attr(href) ")"; font-size: 0.85em; }
}`;

export function renderHtmlReport(document: ReportDocument): string {
  return template
    .replace("{{metadata}}", renderMetadata(document))
    .replace("{{summary}}", renderSummary(document))
    .replace("{{priorityActions}}", renderPriorityActions(document))
    .replace("{{intelligence}}", renderIntelligence(document))
    .replace("{{findings}}", renderFindings(document))
    .replace("{{delta}}", renderDelta(document))
    .replace("{{agentMode}}", renderAgentMode(document))
    .replace("{{scannerStatus}}", renderScannerStatus(document))
    .replace("{{evidenceBundle}}", renderEvidenceBundle(document))
    .replace("{{limitations}}", renderLimitations(document));
}

function renderMetadata(document: ReportDocument): string {
  const target = document.target.displayName
    ? `${document.target.displayName} (${document.target.value})`
    : document.target.value;
  const metadata = [
    renderDetail("Scan ID", `<code>${escapeHtml(document.scanId)}</code>`, "metadata-item"),
    renderDetail("Workspace ID", `<code>${escapeHtml(document.workspaceId)}</code>`, "metadata-item"),
    renderDetail("Target", `<code>${escapeHtml(target)}</code>`, "metadata-item"),
    renderDetail("Target type", escapeHtml(document.target.kind), "metadata-item"),
    renderDetail("Started", escapeHtml(document.run.startedAt), "metadata-item"),
    renderDetail("Finished", escapeHtml(document.run.finishedAt), "metadata-item"),
    renderDetail("Duration", escapeHtml(formatDuration(document.run.durationMs)), "metadata-item"),
    renderDetail("Mode", escapeHtml(document.run.modeLabel ?? document.run.mode), "metadata-item"),
    document.agentMode?.modeLabel
      ? renderDetail("Agent mode", escapeHtml(document.agentMode.modeLabel), "metadata-item")
      : "",
    document.run.git?.branch
      ? renderDetail("Git branch", `<code>${escapeHtml(document.run.git.branch)}</code>`, "metadata-item")
      : "",
    document.run.git?.commit
      ? renderDetail("Commit", `<code>${escapeHtml(document.run.git.commit)}</code>`, "metadata-item")
      : "",
    document.run.git?.dirty !== undefined
      ? renderDetail("Git state", escapeHtml(document.run.git.dirty ? "dirty worktree" : "clean worktree"), "metadata-item")
      : ""
  ].join("");

  return `<header class="report-hero">
  <div>
    <p class="hero-eyebrow">Hermsec Security Report</p>
    <h1>${escapeHtml(document.workspaceName)}</h1>
    <p class="hero-lede">Generated ${escapeHtml(document.generatedAt)} from scanner-backed evidence for <code>${escapeHtml(document.target.value)}</code>.</p>
    <div class="hero-flags">
      <span class="status-pill">${escapeHtml(document.run.modeLabel ?? document.run.mode)} mode</span>
      ${document.agentMode?.modeLabel ? `<span class="status-pill">${escapeHtml(document.agentMode.modeLabel)}</span>` : ""}
      <span class="status-pill ${document.evidence.redactionApplied ? "redaction-on" : "redaction-off"}">Redaction ${document.evidence.redactionApplied ? "applied" : "not needed"}</span>
      <span class="status-pill">${escapeHtml(document.summary.generatedWithModel ? "Model explanations" : "Scanner-only explanations")}</span>
    </div>
  </div>
  <dl class="metadata-grid">${metadata}</dl>
</header>`;
}

function renderSummary(document: ReportDocument): string {
  const metrics = [
    { label: "Total", value: document.summary.total, detail: "findings", className: "total" },
    { label: "Critical", value: document.summary.critical, detail: "highest urgency", className: "critical" },
    { label: "High", value: document.summary.high, detail: "prioritize", className: "high" },
    { label: "Medium", value: document.summary.medium, detail: "schedule", className: "medium" },
    { label: "Low", value: document.summary.low, detail: "track", className: "low" },
    { label: "Info", value: document.summary.info, detail: "review", className: "info" },
    { label: "Secrets", value: document.summary.secrets, detail: "redaction-aware", className: "secret" },
    { label: "Confirmed CVEs", value: document.summary.confirmedCves, detail: "from evidence", className: "cve" },
    { label: "Known exploited", value: document.summary.knownExploited, detail: "intel matches", className: "kev" },
    { label: "Scanner failures", value: document.summary.scannerFailures, detail: "tool issues", className: "failure" }
  ];
  const highestSeverity = severityOrder.find((severity) => document.summary[severity] > 0);
  const summaryText = highestSeverity
    ? `${titleCase(highestSeverity)} severity findings should be reviewed before lower-risk work.`
    : "No findings were reported by the configured scanners.";
  const modelText = document.summary.generatedWithModel
    ? "Model explanations were generated from scanner evidence."
    : "Scanner-only explanation unavailable; this report uses deterministic scanner evidence only.";

  return `<section class="section summary-card">
  <div class="summary-topline">
    <div>
      <p class="section-kicker">Executive Summary</p>
      <h2>${escapeHtml(summaryText)}</h2>
    </div>
    <p class="summary-status">${escapeHtml(modelText)}</p>
  </div>
  <div class="summary-grid">${metrics
    .map((metric) => renderMetric(metric.label, metric.value, metric.detail, metric.className))
    .join("")}</div>
</section>`;
}

function renderPriorityActions(document: ReportDocument): string {
  const findings = [...document.findings].sort(compareFindings).slice(0, 5);
  const actions = findings.map((finding) => {
    const explanation = document.explanations[finding.id];
    const fix = explanation?.suggestedFix ?? finding.remediation;
    return `<li>
      <div>
        <div class="action-title">
          <span class="badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
          <strong>${escapeHtml(finding.title)}</strong>
        </div>
        <p class="action-fix">${escapeHtml(fix)}</p>
      </div>
    </li>`;
  });
  return `<section class="section">
  <div class="section-header">
    <div>
      <p class="section-kicker">Triage</p>
      <h2>Priority Actions</h2>
    </div>
  </div>
  ${actions.length > 0 ? `<ol class="action-list">${actions.join("")}</ol>` : `<p class="empty-state">No findings require action.</p>`}
</section>`;
}

function renderIntelligence(document: ReportDocument): string {
  const cards = document.intelligence.map((item) => {
    const identifiers = [
      ...item.identifiers.cve,
      ...item.identifiers.ghsa,
      ...item.identifiers.osv,
      ...item.identifiers.cwe
    ];
    const identifierTags = identifiers.length > 0 ? renderTags(identifiers, "subtle") : "";
    const reasons = item.reasons.length > 0
      ? `<ul class="limitations-list">${item.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>`
      : "";
    return `<article class="finding ${item.knownExploited ? "critical" : item.severity === "unknown" ? "info" : item.severity}">
  <div class="finding-title-row">
    <h3>${escapeHtml(item.title)}</h3>
    <div class="badge-row">
      <span class="badge ${item.knownExploited ? "critical" : item.severity === "unknown" ? "info" : item.severity}">${escapeHtml(item.priority.toUpperCase())}</span>
      ${item.knownExploited ? `<span class="badge critical">KNOWN EXPLOITED</span>` : ""}
    </div>
  </div>
  <dl class="finding-meta">
    ${renderDetail("Source", escapeHtml(item.source))}
    ${renderDetail("Package", `<code>${escapeHtml(item.packageLabel)}</code>`)}
    ${item.fixVersion ? renderDetail("Fixed version", `<code>${escapeHtml(item.fixVersion)}</code>`) : ""}
    ${item.findingIds.length > 0 ? renderDetail("Related findings", formatIds(item.findingIds)) : ""}
    ${identifierTags ? renderDetail("Identifiers", identifierTags) : ""}
    ${renderDetail("Advisory", `<a href="${escapeHtml(item.url)}">${escapeHtml(item.url)}</a>`)}
  </dl>
  <div class="finding-content-grid">
    <div class="finding-block full">
      <h4>Why It Matters</h4>
      <p>${escapeHtml(item.whyItMatters)}</p>
    </div>
    ${reasons ? `<div class="finding-block full"><h4>Match Reasons</h4>${reasons}</div>` : ""}
  </div>
</article>`;
  });

  return `<section class="section">
  <div class="section-header">
    <div>
      <p class="section-kicker">Vulnerability Intelligence</p>
      <h2>KEV and Advisory Matches</h2>
    </div>
  </div>
  ${cards.length > 0 ? cards.join("") : `<p class="empty-state">No KEV or advisory intelligence matched the scanned dependency inventory or scanner identifiers for this run.</p>`}
</section>`;
}

function renderFindings(document: ReportDocument): string {
  const groups = severityOrder
    .map((severity) => {
      const findings = document.findings.filter((finding) => finding.severity === severity).sort(compareFindings);
      if (findings.length === 0) {
        return "";
      }
      return `<div class="severity-group">
        <div class="severity-heading">
          <h3>${severity.toUpperCase()}</h3>
          <span class="badge ${severity}">${findings.length} ${findings.length === 1 ? "finding" : "findings"}</span>
        </div>
        ${findings.map((finding) => renderFinding(document, finding)).join("")}
      </div>`;
    })
    .filter(Boolean)
    .join("");
  return `<section class="section">
  <div class="section-header">
    <div>
      <p class="section-kicker">Evidence Review</p>
      <h2>Findings</h2>
    </div>
  </div>
  ${groups || `<p class="empty-state">No findings were reported by the configured scanners.</p>`}
</section>`;
}

function renderFinding(document: ReportDocument, finding: ReportFinding): string {
  const explanation = document.explanations[finding.id];
  const agent = findingAgentMetadata(document, finding);
  const identifiers = [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
    ...(finding.cwe ?? [])
  ];
  const packageDetails = finding.package
    ? `${finding.package.ecosystem}:${finding.package.name}${finding.package.installedVersion ? `@${finding.package.installedVersion}` : ""}`
    : undefined;
  const metadata = [
    renderDetail("ID", `<code>${escapeHtml(finding.id)}</code>`),
    renderDetail("Category", escapeHtml(titleCase(finding.category))),
    renderDetail("Tool", escapeHtml(displayScannerName(finding.tool))),
    renderDetail("Confidence", escapeHtml(finding.confidence)),
    renderDetail("Location", `<code>${escapeHtml(formatLocation(finding))}</code>`),
    finding.ruleId ? renderDetail("Rule", `<code>${escapeHtml(finding.ruleId)}</code>`) : "",
    packageDetails ? renderDetail("Package", `<code>${escapeHtml(packageDetails)}</code>`) : "",
    renderDetail("Fingerprint", `<code>${escapeHtml(finding.fingerprint)}</code>`),
    agent.sourceLabels.length > 0 ? renderDetail("Source", renderTags(agent.sourceLabels.map(labelize), "subtle")) : "",
    agent.judgeStatus ? renderDetail("Judge", `<span class="badge subtle">${escapeHtml(labelize(agent.judgeStatus))}</span>`) : "",
    identifiers.length > 0 ? renderDetail("Identifiers", renderTags(identifiers, "subtle")) : ""
  ].join("");
  const safeNextSteps = explanation?.safeNextSteps?.length
    ? `<div class="finding-block full">
        <h4>Safe Next Steps</h4>
        <ol>${explanation.safeNextSteps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
      </div>`
    : "";

  return `<article class="finding ${finding.severity}">
  <div class="finding-title-row">
    <h3>${escapeHtml(finding.title)}</h3>
    <div class="badge-row">
      <span class="badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
      <span class="badge subtle">${escapeHtml(finding.confidence)}</span>
      ${agent.sourceLabels.map((label) => `<span class="badge subtle">${escapeHtml(labelize(label))}</span>`).join("")}
      ${agent.judgeStatus ? `<span class="badge subtle">Judge: ${escapeHtml(labelize(agent.judgeStatus))}</span>` : ""}
    </div>
  </div>
  <dl class="finding-meta">${metadata}</dl>
  <div class="finding-content-grid">
    <div class="finding-block full">
      <h4>Evidence</h4>
      <pre class="evidence-block">${escapeHtml(finding.evidence)}</pre>
    </div>
    <div class="finding-block">
      <h4>Description</h4>
      <p>${escapeHtml(finding.description)}</p>
    </div>
    <div class="finding-block">
      <h4>Explanation</h4>
      <p>${escapeHtml(explanation?.evidenceSummary ?? "Scanner-only explanation unavailable.")}</p>
    </div>
    ${explanation?.impact ? renderFindingBlock("Impact", explanation.impact) : ""}
    ${explanation?.confidenceReason ? renderFindingBlock("Confidence Reason", explanation.confidenceReason) : ""}
    <div class="finding-block full">
      <h4>Suggested Fix</h4>
      <p>${escapeHtml(explanation?.suggestedFix ?? finding.remediation)}</p>
    </div>
    ${safeNextSteps}
  </div>
</article>`;
}

function renderDelta(document: ReportDocument): string {
  const delta = document.delta;
  if (!delta) {
    return `<section class="section">
  <p class="section-kicker">History</p>
  <h2>Delta</h2>
  <p class="empty-state">No previous scan was available for comparison.</p>
</section>`;
  }
  return `<section class="section">
  <p class="section-kicker">History</p>
  <h2>Delta</h2>
  <p>${escapeHtml(delta.summaryText ?? "Delta was calculated from stable finding fingerprints.")}</p>
  <div class="delta-grid">
    ${delta.baseScanId ? renderDeltaItem("Base scan", [delta.baseScanId]) : ""}
    ${renderDeltaItem("Current scan", [delta.currentScanId])}
    ${renderDeltaItem("New", delta.newFindingIds, "high")}
    ${renderDeltaItem("Fixed", delta.fixedFindingIds, "low")}
    ${renderDeltaItem("Unchanged", delta.unchangedFindingIds, "info")}
    ${renderDeltaItem("Worsened", delta.worsenedFindingIds, "critical")}
    ${renderDeltaItem("Improved", delta.improvedFindingIds, "low")}
  </div>
</section>`;
}

function renderAgentMode(document: ReportDocument): string {
  const metadata = document.agentMode;
  if (!metadata) {
    return "";
  }

  const aggregator = metadata.aggregatorModel ?? formatAggregator(metadata.aggregator);
  const details = [
    renderDetail("Mode", escapeHtml(metadata.modeLabel ?? metadata.mode ?? document.run.modeLabel ?? document.run.mode)),
    metadata.scanMode ? renderDetail("Scan mode", escapeHtml(metadata.scanMode)) : "",
    metadata.candidateFindingCount !== undefined
      ? renderDetail("Candidates", escapeHtml(String(metadata.candidateFindingCount)))
      : "",
    metadata.acceptedFindingCount !== undefined
      ? renderDetail("Accepted", escapeHtml(String(metadata.acceptedFindingCount)))
      : "",
    metadata.rejectedFindingCount !== undefined
      ? renderDetail("Rejected", escapeHtml(String(metadata.rejectedFindingCount)))
      : "",
    metadata.needsHumanReviewCount !== undefined
      ? renderDetail("Needs review", escapeHtml(String(metadata.needsHumanReviewCount)))
      : "",
    aggregator ? renderDetail("Aggregator", `<code>${escapeHtml(aggregator)}</code>`) : "",
    metadata.totalAgentRuntimeMs !== undefined
      ? renderDetail("Agent runtime", escapeHtml(formatDuration(metadata.totalAgentRuntimeMs)))
      : ""
  ].join("");

  const agentRows = (metadata.agents ?? [])
    .map((agent) => {
      const providerModel = [agent.provider, agent.model].filter(Boolean).join(" / ") || "not recorded";
      return `<tr>
        <td>${escapeHtml(agent.label ?? agent.id)}</td>
        <td>${escapeHtml(agent.role ?? "agent")}</td>
        <td><code>${escapeHtml(providerModel)}</code></td>
        <td class="duration">${escapeHtml(formatDuration(agent.runtimeMs))}</td>
      </tr>`;
    })
    .join("");

  return `<section class="section">
  <p class="section-kicker">Agents</p>
  <h2>Agent Mode</h2>
  <dl class="key-values">${details}</dl>
  ${agentRows ? `<table class="compact-table">
    <thead><tr><th>Agent</th><th>Role</th><th>Provider / Model</th><th>Runtime</th></tr></thead>
    <tbody>${agentRows}</tbody>
  </table>` : `<p class="empty-state">No per-agent provider/model metadata was recorded.</p>`}
</section>`;
}

function renderScannerStatus(document: ReportDocument): string {
  const rows = document.tools
    .map((tool) => `<tr>
        <td>${escapeHtml(displayScannerName(tool.label))}</td>
        <td><span class="status-pill ${tool.status}">${escapeHtml(tool.status)}</span></td>
        <td class="duration">${escapeHtml(formatDuration(tool.durationMs))}</td>
        <td>${escapeHtml(tool.message)}</td>
      </tr>`)
    .join("");

  return `<section class="section">
  <p class="section-kicker">Scanners</p>
  <h2>Scanner Status</h2>
  ${rows ? `<table class="compact-table">
    <thead><tr><th>Tool</th><th>Status</th><th>Duration</th><th>Message</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>` : `<p class="empty-state">No scanner status entries were recorded.</p>`}
</section>`;
}

function renderEvidenceBundle(document: ReportDocument): string {
  const artifactRows = document.evidence.rawArtifacts
    .map((artifact) => `<tr>
      <td>${escapeHtml(displayScannerName(artifact.scanner))}</td>
      <td><code>${escapeHtml(artifact.path)}</code></td>
      <td>${escapeHtml(artifact.status)}</td>
      <td>${escapeHtml(String(artifact.sizeBytes))}</td>
      <td><code>${escapeHtml(artifact.sha256)}</code></td>
    </tr>`)
    .join("");

  return `<section class="section">
  <p class="section-kicker">Evidence</p>
  <h2>Bundle</h2>
  <dl class="key-values">
    ${renderDetail("Bundle ID", `<code>${escapeHtml(document.evidence.bundleId)}</code>`)}
    ${renderDetail("Redaction", escapeHtml(document.evidence.redactionApplied ? "applied" : "not needed"))}
  </dl>
  ${artifactRows ? `<table class="compact-table">
    <thead><tr><th>Scanner</th><th>Artifact</th><th>Status</th><th>Bytes</th><th>SHA-256</th></tr></thead>
    <tbody>${artifactRows}</tbody>
  </table>` : `<p class="empty-state">No raw artifacts were stored for this report.</p>`}
</section>`;
}

function renderLimitations(document: ReportDocument): string {
  return `<section class="section">
  <p class="section-kicker">Scope</p>
  <h2>Limitations</h2>
  ${document.limitations.length > 0
    ? `<ul class="limitations-list">${document.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join("")}</ul>`
    : `<p class="empty-state">No additional limitations were recorded.</p>`}
</section>`;
}

function findingAgentMetadata(
  document: ReportDocument,
  finding: ReportFinding
): { sourceLabels: string[]; judgeStatus?: string } {
  const mapped = document.agentMode?.findings?.[finding.id];
  const sourceLabels = unique([
    ...arrayValue(finding.sourceLabels),
    ...arrayValue(finding.sourceLabel),
    ...arrayValue(mapped?.sourceLabels),
    ...arrayValue(mapped?.sourceLabel)
  ]);
  const judgeStatus = firstNonEmpty(finding.judgeStatus, mapped?.judgeStatus);
  return {
    sourceLabels,
    ...(judgeStatus ? { judgeStatus } : {})
  };
}

function formatAggregator(value: { agentId?: string; provider?: string; model?: string; label?: string } | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const providerModel = [value.provider, value.model].filter(Boolean).join(" / ");
  return firstNonEmpty(providerModel, value.label, value.agentId);
}

function arrayValue(value: string | readonly string[] | undefined): string[] {
  if (!value) {
    return [];
  }
  return (Array.isArray(value) ? value : [value]).map((item) => item.trim()).filter(Boolean);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => value !== undefined && value.trim().length > 0);
}

function labelize(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function formatIds(ids: readonly string[]): string {
  return ids.length > 0
    ? `<div class="id-list">${ids.map((id) => `<code class="id-pill">${escapeHtml(id)}</code>`).join("")}</div>`
    : `<span class="muted">None</span>`;
}

function formatLocation(finding: ReportFinding): string {
  if (!finding.location) {
    return "No source location";
  }
  const line =
    finding.location.startLine !== undefined
      ? finding.location.endLine !== undefined && finding.location.endLine !== finding.location.startLine
        ? `:${finding.location.startLine}-${finding.location.endLine}`
        : `:${finding.location.startLine}`
      : "";
  return `${finding.location.file}${line}`;
}

function formatDuration(durationMs: number | undefined): string {
  if (durationMs === undefined) {
    return "n/a";
  }
  if (durationMs >= 1000) {
    const seconds = durationMs / 1000;
    return `${seconds >= 10 ? seconds.toFixed(0) : seconds.toFixed(1)} s`;
  }
  return `${durationMs} ms`;
}

function renderMetric(label: string, value: number, detail: string, className: string): string {
  return `<div class="metric ${className}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(String(value))}</strong>
    <small>${escapeHtml(detail)}</small>
  </div>`;
}

function renderDetail(label: string, content: string, className = "detail-item"): string {
  return `<div class="${className}"><dt>${escapeHtml(label)}</dt><dd>${content}</dd></div>`;
}

function renderTags(values: readonly string[], className = ""): string {
  const classes = ["badge", className].filter(Boolean).join(" ");
  return values.map((value) => `<span class="${classes}">${escapeHtml(value)}</span>`).join("");
}

function renderFindingBlock(title: string, value: string): string {
  return `<div class="finding-block">
    <h4>${escapeHtml(title)}</h4>
    <p>${escapeHtml(value)}</p>
  </div>`;
}

function renderDeltaItem(label: string, ids: readonly string[], className = ""): string {
  return `<div class="delta-item">
    <strong>${escapeHtml(label)}</strong>
    ${ids.length > 0 ? `<div class="id-list">${ids.map((id) => `<code class="id-pill ${className}">${escapeHtml(id)}</code>`).join("")}</div>` : formatIds(ids)}
  </div>`;
}

function titleCase(value: string): string {
  return value
    .split(/[\s-]+/)
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
