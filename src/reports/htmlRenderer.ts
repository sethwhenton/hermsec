import type { Finding } from "../shared/types.js";
import type { ReportDocument } from "./schema.js";
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
  <main>
    {{metadata}}
    {{summary}}
    {{priorityActions}}
    {{findings}}
    {{delta}}
    {{scannerStatus}}
    {{limitations}}
  </main>
</body>
</html>`;

export const defaultReportCss = `:root {
  color-scheme: light;
  --bg: #f8fafc;
  --panel: #ffffff;
  --text: #172033;
  --muted: #5a6475;
  --border: #d8dee8;
  --critical: #8f1d1d;
  --high: #b34300;
  --medium: #986a00;
  --low: #2f6f4e;
  --info: #315f8f;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}
main {
  max-width: 1120px;
  margin: 0 auto;
  padding: 32px 20px 48px;
}
section, header {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin: 0 0 16px;
  padding: 18px;
}
h1, h2, h3 { margin: 0 0 10px; line-height: 1.2; }
p { margin: 0 0 10px; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; border-bottom: 1px solid var(--border); padding: 8px; vertical-align: top; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 0.95em; }
.muted { color: var(--muted); }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(112px, 1fr)); gap: 10px; }
.metric { border: 1px solid var(--border); border-radius: 6px; padding: 10px; background: #fbfcff; }
.metric strong { display: block; font-size: 1.4rem; }
.finding { border-left: 4px solid var(--info); }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.badge { display: inline-block; border: 1px solid var(--border); border-radius: 999px; padding: 2px 8px; margin: 0 6px 6px 0; font-size: 0.8rem; }
.badge.critical { color: var(--critical); }
.badge.high { color: var(--high); }
.badge.medium { color: var(--medium); }
.badge.low { color: var(--low); }
.badge.info { color: var(--info); }
@media print {
  body { background: #fff; }
  main { max-width: none; padding: 0; }
  section, header { break-inside: avoid; border-color: #bbb; }
  a[href]::after { content: " (" attr(href) ")"; font-size: 0.85em; }
}`;

export function renderHtmlReport(document: ReportDocument): string {
  return template
    .replace("{{metadata}}", renderMetadata(document))
    .replace("{{summary}}", renderSummary(document))
    .replace("{{priorityActions}}", renderPriorityActions(document))
    .replace("{{findings}}", renderFindings(document))
    .replace("{{delta}}", renderDelta(document))
    .replace("{{scannerStatus}}", renderScannerStatus(document))
    .replace("{{limitations}}", renderLimitations(document));
}

function renderMetadata(document: ReportDocument): string {
  const git = document.run.git?.commit
    ? `<p><strong>Commit:</strong> <code>${escapeHtml(document.run.git.commit)}</code></p>`
    : "";
  return `<header>
  <h1>Hermsec Security Report</h1>
  <p class="muted">Generated ${escapeHtml(document.generatedAt)} for ${escapeHtml(document.workspaceName)}</p>
  <p><strong>Scan:</strong> <code>${escapeHtml(document.scanId)}</code></p>
  <p><strong>Target:</strong> <code>${escapeHtml(document.target.value)}</code></p>
  <p><strong>Mode:</strong> ${escapeHtml(document.run.mode)}</p>
  ${git}
  <p><strong>Redaction:</strong> ${document.evidence.redactionApplied ? "applied" : "not needed"}</p>
</header>`;
}

function renderSummary(document: ReportDocument): string {
  const metrics = [
    ["Total", document.summary.total],
    ["Critical", document.summary.critical],
    ["High", document.summary.high],
    ["Medium", document.summary.medium],
    ["Low", document.summary.low],
    ["Info", document.summary.info],
    ["Secrets", document.summary.secrets],
    ["Confirmed CVEs", document.summary.confirmedCves],
    ["Scanner failures", document.summary.scannerFailures]
  ];
  return `<section>
  <h2>Executive Summary</h2>
  <div class="summary-grid">${metrics
    .map(([label, value]) => `<div class="metric"><span>${escapeHtml(String(label))}</span><strong>${value}</strong></div>`)
    .join("")}</div>
  <p class="muted">${document.summary.generatedWithModel ? "Model explanations were generated from scanner evidence." : "Scanner-only explanation unavailable; this report uses deterministic scanner evidence only."}</p>
</section>`;
}

function renderPriorityActions(document: ReportDocument): string {
  const findings = [...document.findings].sort(compareFindings).slice(0, 5);
  const actions = findings.map((finding) => {
    const explanation = document.explanations[finding.id];
    const fix = explanation?.suggestedFix ?? finding.remediation;
    return `<li><strong>${escapeHtml(finding.title)}</strong>: ${escapeHtml(fix)}</li>`;
  });
  return `<section>
  <h2>Priority Actions</h2>
  ${actions.length > 0 ? `<ol>${actions.join("")}</ol>` : "<p>No findings require action.</p>"}
</section>`;
}

function renderFindings(document: ReportDocument): string {
  const groups = severityOrder
    .map((severity) => {
      const findings = document.findings.filter((finding) => finding.severity === severity).sort(compareFindings);
      if (findings.length === 0) {
        return "";
      }
      return `<h3>${severity.toUpperCase()}</h3>${findings.map((finding) => renderFinding(document, finding)).join("")}`;
    })
    .filter(Boolean)
    .join("");
  return `<section>
  <h2>Findings</h2>
  ${groups || "<p>No findings were reported by the configured scanners.</p>"}
</section>`;
}

function renderFinding(document: ReportDocument, finding: Finding): string {
  const explanation = document.explanations[finding.id];
  const identifiers = [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
    ...(finding.cwe ?? [])
  ];
  const location = finding.location
    ? `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : "No source location";
  return `<article class="finding ${finding.severity}">
  <h3>${escapeHtml(finding.title)}</h3>
  <p>
    <span class="badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
    <span class="badge">${escapeHtml(finding.confidence)}</span>
    <span class="badge">${escapeHtml(finding.tool)}</span>
  </p>
  <p><strong>Location:</strong> <code>${escapeHtml(location)}</code></p>
  <p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
  <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
  <p><strong>Suggested fix:</strong> ${escapeHtml(explanation?.suggestedFix ?? finding.remediation)}</p>
  <p><strong>Explanation:</strong> ${escapeHtml(explanation?.evidenceSummary ?? "Scanner-only explanation unavailable.")}</p>
  ${identifiers.length > 0 ? `<p><strong>Identifiers from evidence:</strong> ${identifiers.map((id) => `<code>${escapeHtml(id)}</code>`).join(", ")}</p>` : ""}
</article>`;
}

function renderDelta(document: ReportDocument): string {
  const delta = document.delta;
  if (!delta) {
    return `<section><h2>Delta Since Previous Scan</h2><p>No previous scan was available for comparison.</p></section>`;
  }
  return `<section>
  <h2>Delta Since Previous Scan</h2>
  <p>${escapeHtml(delta.summaryText ?? "Delta was calculated from stable finding fingerprints.")}</p>
  <table>
    <thead><tr><th>Status</th><th>Finding IDs</th></tr></thead>
    <tbody>
      <tr><td>New</td><td>${formatIds(delta.newFindingIds)}</td></tr>
      <tr><td>Fixed</td><td>${formatIds(delta.fixedFindingIds)}</td></tr>
      <tr><td>Unchanged</td><td>${formatIds(delta.unchangedFindingIds)}</td></tr>
      <tr><td>Worsened</td><td>${formatIds(delta.worsenedFindingIds)}</td></tr>
      <tr><td>Improved</td><td>${formatIds(delta.improvedFindingIds)}</td></tr>
    </tbody>
  </table>
</section>`;
}

function renderScannerStatus(document: ReportDocument): string {
  return `<section>
  <h2>Scanner Status</h2>
  <table>
    <thead><tr><th>Tool</th><th>Status</th><th>Duration</th><th>Message</th></tr></thead>
    <tbody>${document.tools
      .map((tool) => `<tr><td>${escapeHtml(tool.label)}</td><td>${escapeHtml(tool.status)}</td><td>${tool.durationMs ?? ""}</td><td>${escapeHtml(tool.message)}</td></tr>`)
      .join("")}</tbody>
  </table>
</section>`;
}

function renderLimitations(document: ReportDocument): string {
  return `<section>
  <h2>Limitations</h2>
  <ul>${document.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join("")}</ul>
</section>`;
}

function formatIds(ids: readonly string[]): string {
  return ids.length > 0 ? ids.map((id) => `<code>${escapeHtml(id)}</code>`).join(", ") : "None";
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
