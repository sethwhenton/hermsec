(function () {
  "use strict";

  const R = HERMSEC_REPORT;
  const adjMap = Object.fromEntries(R.adjudications.map((a) => [a.findingId, a]));

  function esc(str) {
    if (str == null) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badge(severity) {
    return `<span class="badge badge-${esc(severity)}">${esc(severity)}</span>`;
  }

  function verdictBadge(verdict) {
    const map = {
      confirmed: "confirmed",
      "likely exploitable": "likely",
      "needs human context": "context",
      "probably false positive": "info",
      "best-practice recommendation": "info"
    };
    const cls = map[verdict] || "info";
    return `<span class="badge badge-${cls}">${esc(verdict)}</span>`;
  }

  function statusIcon(status) {
    const icons = { completed: "\u2713", running: "\u25CB", waiting: "\u00B7", skipped: "\u2298", failed: "\u2717" };
    return icons[status] || "?";
  }

  function formatDate(iso) {
    if (!iso) return "Not recorded";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "Not recorded";
    return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function formatDurationMs(ms) {
    const value = Number(ms);
    if (!Number.isFinite(value) || value <= 0) return "not recorded";
    if (value < 1000) return `${Math.round(value)}ms`;
    const seconds = value / 1000;
    if (seconds < 60) return `${seconds.toFixed(seconds >= 10 ? 0 : 1)}s`;
    const minutes = Math.floor(seconds / 60);
    const remaining = Math.round(seconds % 60);
    return `${minutes}m ${remaining}s`;
  }

  function labelize(value) {
    return String(value || "")
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/\b\w/g, (m) => m.toUpperCase());
  }

  function judgeBadge(status) {
    if (!status) return "";
    const normalized = String(status).toLowerCase().replace(/[\s_]+/g, "-");
    const cls =
      normalized === "accepted" ? "confirmed" :
      normalized === "rejected" ? "info" :
      normalized === "needs-human-review" ? "context" :
      "info";
    return `<span class="badge badge-${cls}">Judge: ${esc(labelize(status))}</span>`;
  }

  function findingSourceBadges(f) {
    return (f.sourceLabels || [])
      .map((label) => `<span class="badge badge-info">${esc(labelize(label))}</span>`)
      .join("");
  }

  function renderToolbar() {
    document.getElementById("screen-toolbar").innerHTML = `
      <div class="toolbar-left">
        <span class="toolbar-label">Executive One-Pager</span>
      </div>
      <button class="btn btn-primary" id="btn-print" type="button">Save as PDF</button>`;
  }

  function renderCover() {
    const scan = R.scan;
    const p = R.posture;
    const commitShort =
      scan.gitCommit && scan.gitCommit.length > 7 ? scan.gitCommit.slice(0, 7) : scan.gitCommit;
    const assistLabel = R.assist?.label || scan.assistModeLabel || "Deep assisted scan";
    const agentMode = R.agentMode || null;

    document.getElementById("op-cover").innerHTML = `
      <div class="op-cover-top">
        <div class="op-brand">
          <h1>Security Report</h1>
          <p class="op-brand-sub">${esc(scan.projectName)}</p>
        </div>
        <span class="op-doc-type">Executive Summary</span>
      </div>
      <div class="bezel">
        <div class="bezel-inner posture-band posture-${esc(p.class)}">
          <span class="posture-pill">${esc(p.grade)}</span>
          <div>
            <p class="posture-headline">${esc(p.headline)}</p>
            <p class="posture-detail">${esc(p.detail)}</p>
          </div>
        </div>
      </div>
      <div class="op-meta-grid">
        <div class="op-meta-item"><span>Scan ID</span><strong>${esc(scan.scanId)}</strong></div>
        ${agentMode ? `<div class="op-meta-item"><span>Agent mode</span><strong>${esc(agentMode.modeLabel)}</strong></div>` : ""}
        ${agentMode ? `<div class="op-meta-item"><span>Agent findings</span><strong>${esc(agentMode.acceptedFindingCount)} accepted / ${esc(agentMode.needsHumanReviewCount)} review</strong></div>` : ""}
        ${agentMode ? `<div class="op-meta-item"><span>Agent runtime</span><strong>${esc(agentMode.totalAgentRuntime || formatDurationMs(agentMode.totalAgentRuntimeMs))}</strong></div>` : ""}
        <div class="op-meta-item"><span>Assist mode</span><strong>${esc(assistLabel)}</strong></div>
        <div class="op-meta-item"><span>Duration</span><strong>${esc(scan.duration)}</strong></div>
        <div class="op-meta-item"><span>Branch</span><code>${esc(scan.gitBranch)}</code></div>
        <div class="op-meta-item"><span>Commit</span><code>${esc(commitShort)}</code></div>
        <div class="op-meta-item"><span>Dirty tree</span><strong>${scan.dirtyWorkingTree ? "Yes" : "No"}</strong></div>
        <div class="op-meta-item"><span>Started</span><strong>${formatDate(scan.startedAt)}</strong></div>
        <div class="op-meta-item"><span>Finished</span><strong>${formatDate(scan.finishedAt)}</strong></div>
        <div class="op-meta-item"><span>Report generated</span><strong>${formatDate(scan.reportGeneratedAt)}</strong></div>
      </div>`;
  }

  function renderSummary() {
    const s = R.summary;
    const sevSegments = [
      { key: "critical", count: s.critical },
      { key: "high", count: s.high },
      { key: "medium", count: s.medium },
      { key: "low", count: s.low },
      { key: "info", count: s.info }
    ]
      .filter((x) => x.count > 0)
      .map(
        (x) =>
          `<div class="severity-bar-segment ${x.key}" style="flex-grow:${x.count}" title="${x.key}: ${x.count}"></div>`
      )
      .join("");

    const metrics = [
      { label: "Critical", value: s.critical, cls: "critical" },
      { label: "High", value: s.high, cls: "high" },
      { label: "Medium", value: s.medium, cls: "medium" },
      { label: "Total findings", value: s.totalFindings, cls: "" },
      { label: "Secrets", value: s.secrets, cls: "alert" },
      { label: "Confirmed CVEs", value: s.confirmedCves, cls: "accent" },
      { label: "Known exploited", value: s.knownExploited, cls: "critical" },
      { label: "Fix now", value: R.fixPlan.fixNow.length, cls: "accent" },
      ...(R.agentMode
        ? [
            { label: "Candidates", value: R.agentMode.candidateFindingCount, cls: "" },
            { label: "Accepted", value: R.agentMode.acceptedFindingCount, cls: "accent" },
            { label: "Rejected", value: R.agentMode.rejectedFindingCount, cls: "" },
            { label: "Needs review", value: R.agentMode.needsHumanReviewCount, cls: "alert" }
          ]
        : [])
    ]
      .map(
        (m) =>
          `<div class="metric-cell ${esc(m.cls)}"><span class="metric-cell-value">${m.value}</span><span class="metric-cell-label">${esc(m.label)}</span></div>`
      )
      .join("");

    document.getElementById("op-summary").innerHTML = `
      <h2 class="op-section-title" id="op-summary-title">Executive summary</h2>
      <p class="op-section-desc">At-a-glance severity distribution and key counts from the Hermsec scan.</p>
      <div class="severity-bar-wrap">
        <div class="severity-bar">${sevSegments}</div>
      </div>
      <div class="metric-grid">${metrics}</div>`;
  }

  function renderPipeline() {
    const chips = R.scanners
      .map(
        (s) => `
      <div class="pipeline-chip">
        <span class="pipeline-icon ${esc(s.status)}" aria-hidden="true">${statusIcon(s.status)}</span>
        <span class="pipeline-name">${esc(s.name)}</span>
        <span class="pipeline-count">${s.findings} · ${esc(s.duration)}</span>
      </div>`
      )
      .join("");
    const agentChips = R.agentMode
      ? (R.agentMode.agents || [])
          .map(
            (agent) => `
      <div class="pipeline-chip">
        <span class="pipeline-icon completed" aria-hidden="true">A</span>
        <span class="pipeline-name">${esc(agent.label || agent.id)}</span>
        <span class="pipeline-count">${esc([agent.provider, agent.model].filter(Boolean).join(" / ") || "model not recorded")}</span>
      </div>`
          )
          .join("")
      : "";

    document.getElementById("op-pipeline").innerHTML = `
      <h2 class="op-section-title" id="op-pipeline-title">Scan integrity</h2>
      <p class="op-section-desc">Pipeline status across ${R.scanners.length} tools — ${R.summary.scannerFailures} failure${R.summary.scannerFailures !== 1 ? "s" : ""} noted.</p>
      <div class="pipeline-strip">${chips}${agentChips}</div>`;
  }

  function renderFindingFull(f) {
    const adj = adjMap[f.id];
    const sourceBadges = findingSourceBadges(f);
    const judge = judgeBadge(f.judgeStatus);
    const adjBlock = adj
      ? `<h4>Agent verdict</h4><p>${verdictBadge(adj.verdict)} ${esc(adj.reasoning)}</p>`
      : "";

    return `
      <article class="finding-card bezel" data-severity="${esc(f.severity)}">
        <div class="bezel-inner finding-card-inner">
          <div class="finding-header">
            <span class="finding-id">${esc(f.id)}</span>
            ${badge(f.severity)}
            <span class="badge badge-info">${esc(f.confidence)}</span>
            ${sourceBadges}
            ${judge}
            ${adj ? verdictBadge(adj.verdict) : ""}
            <div class="finding-title">${esc(f.title)}</div>
          </div>
          <div class="finding-meta">
            <span>${esc(f.category)}</span>
            <span>${esc(f.tool)}</span>
            <span><code>${esc(f.file)}${f.line ? ":" + f.line : ""}</code></span>
          </div>
          <div class="finding-body">
            <h4>Evidence</h4>
            <pre class="evidence-block">${esc(f.evidence)}</pre>
            <h4>Impact</h4>
            <p>${esc(f.impact)}</p>
            <h4>Remediation</h4>
            <p>${esc(f.remediation)}</p>
            ${adjBlock}
          </div>
        </div>
      </article>`;
  }

  function renderFindings() {
    const priority = R.findings.filter((f) => f.severity === "critical" || f.severity === "high");
    const remainder = R.findings.filter((f) => f.severity !== "critical" && f.severity !== "high");

    const priorityHtml = priority.map(renderFindingFull).join("");

    const tableRows = remainder
      .map(
        (f) => `
      <tr>
        <td><code>${esc(f.id)}</code></td>
        <td>${badge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td><code>${esc(f.file)}${f.line ? ":" + f.line : ""}</code></td>
        <td>${esc(f.tool)}</td>
        <td>${esc((f.sourceLabels || []).map(labelize).join(", "))}</td>
        <td>${esc(labelize(f.judgeStatus))}</td>
      </tr>`
      )
      .join("");

    document.getElementById("op-findings").innerHTML = `
      <h2 class="op-section-title" id="op-findings-title">Priority findings</h2>
      <p class="op-section-desc">${priority.length} critical/high findings in full detail; ${remainder.length} medium, low, and info items summarized below.</p>
      <div class="findings-priority">${priorityHtml}</div>
      ${
        remainder.length > 0
          ? `
      <p class="findings-summary-caption">Other findings (${remainder.length})</p>
      <table class="findings-summary-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Location</th>
            <th>Tool</th>
            <th>Source</th>
            <th>Judge</th>
          </tr>
        </thead>
        <tbody>${tableRows}</tbody>
      </table>`
          : ""
      }`;
  }

  function renderFixPlanBlock(title, cls, items) {
    const body =
      items.length > 0
        ? items
            .map(
              (item) => `
          <div class="fixplan-item">
            <h4>${esc(item.title)}</h4>
            <p>IDs: ${item.findingIds.map((id) => esc(id)).join(", ") || "N/A"} · Owner: ${esc(item.owner)} · Effort: ${esc(item.effort)}</p>
            <p>Validate: ${esc(item.validation)}</p>
            <code>${esc(item.command)}</code>
          </div>`
            )
            .join("")
        : `<p style="margin:0;font-size:0.72rem;color:var(--text-muted)">No items</p>`;

    return `
      <div class="fixplan-block">
        <div class="fixplan-block-header ${cls}">${esc(title)}</div>
        <div class="fixplan-block-body">${body}</div>
      </div>`;
  }

  function renderFixPlan() {
    const fp = R.fixPlan;
    document.getElementById("op-fixplan").innerHTML = `
      <h2 class="op-section-title" id="op-fixplan-title">Recommended fix plan</h2>
      <p class="op-section-desc">Prioritized remediation grouped by urgency — ${fp.fixNow.length} immediate, ${fp.fixThisWeek.length} this week.</p>
      <div class="fixplan-stack">
        ${renderFixPlanBlock("Fix now", "fix-now", fp.fixNow)}
        ${renderFixPlanBlock("Fix this week", "fix-week", fp.fixThisWeek)}
        ${renderFixPlanBlock("Monitor", "monitor", fp.monitor)}
        ${renderFixPlanBlock("Needs context", "needs-context", fp.needsContext)}
      </div>`;
  }

  function renderIntel() {
    const kev = R.intelligence.filter((i) => i.knownExploited);
    const cveHighlights = R.intelligence.filter((i) => i.cve && !i.knownExploited);

    function intelCard(i) {
      const ids = [
        ...(i.identifiers?.cve || []),
        ...(i.identifiers?.ghsa || []),
        ...(i.identifiers?.osv || [])
      ];
      return `
      <article class="intel-card bezel ${i.knownExploited ? "kev" : ""}">
        <div class="bezel-inner intel-card-inner">
          <div class="intel-title">${esc(i.title)}</div>
          <div class="intel-meta">
            <span>${esc(i.source)}</span>
            ${badge(i.severity)}
            ${i.knownExploited ? `<span class="badge badge-critical">Known Exploited</span>` : ""}
            ${i.package ? `<span>${esc(i.ecosystem)} / ${esc(i.package)}</span>` : ""}
            ${i.cve ? `<span>${esc(i.cve)}</span>` : ""}
            ${i.fixVersion ? `<span>Fix ${esc(i.fixVersion)}</span>` : ""}
          </div>
          ${ids.length > 0 ? `<div class="finding-tags">${ids.map((id) => `<span class="tag">${esc(id)}</span>`).join("")}</div>` : ""}
          <p class="intel-why"><strong>Why it matters:</strong> ${esc(i.whyItMatters)}</p>
        </div>
      </article>`;
    }

    document.getElementById("op-intel").innerHTML = `
      <h2 class="op-section-title" id="op-intel-title">Vulnerability intelligence</h2>
      <p class="op-section-desc">KEV and advisory records matched against dependency inventory and scanner evidence.</p>
      ${
        kev.length > 0
          ? `<p class="intel-section-label">CISA Known Exploited (${kev.length})</p><div class="intel-list">${kev.map(intelCard).join("")}</div>`
          : ""
      }
      ${
        cveHighlights.length > 0
          ? `<p class="intel-section-label" style="margin-top:0.75rem">Confirmed CVE highlights (${cveHighlights.length})</p><div class="intel-list">${cveHighlights.map(intelCard).join("")}</div>`
          : ""
      }
      ${
        kev.length === 0 && cveHighlights.length === 0
          ? `<div class="empty-state"><strong>No matched advisory intelligence</strong><p>No KEV, OSV, GitHub Advisory, or NVD entries matched this run.</p></div>`
          : ""
      }`;
  }

  function renderAppendix() {
    const ev = R.evidence;
    const limits = ev.limitations.map((l) => `<li>${esc(l)}</li>`).join("");
    const failed = ev.failedScanners
      .map((f) => `<li><strong>${esc(f.name)}</strong> — ${esc(f.reason)}</li>`)
      .join("");
    const paths = ev.artifactPaths.map((p) => `<li><code>${esc(p)}</code></li>`).join("");

    document.getElementById("op-appendix").innerHTML = `
      <h2 class="op-section-title" id="op-appendix-title">Appendix</h2>
      <p class="op-section-desc">Scan limitations, failed tools, and artifact locations.</p>
      <div class="notice">${esc(ev.redactionNote)}</div>
      <div class="appendix-block">
        <h3>Limitations</h3>
        <ul>${limits}</ul>
      </div>
      <div class="appendix-block">
        <h3>Failed scanners</h3>
        <ul>${failed || "<li>None</li>"}</ul>
      </div>
      <div class="appendix-block">
        <h3>Artifact paths</h3>
        <ul>${paths}</ul>
      </div>`;
  }

  function renderFooter() {
    const scan = R.scan;
    document.getElementById("op-footer").textContent =
      `Hermsec · ${scan.projectName} · ${scan.scanId} · Generated ${formatDate(scan.reportGeneratedAt)}`;
  }

  function bindEvents() {
    document.getElementById("btn-print").addEventListener("click", () => window.print());
  }

  function init() {
    renderToolbar();
    renderCover();
    renderSummary();
    renderPipeline();
    renderFindings();
    renderFixPlan();
    renderIntel();
    renderAppendix();
    renderFooter();
    bindEvents();
  }

  init();
})();
