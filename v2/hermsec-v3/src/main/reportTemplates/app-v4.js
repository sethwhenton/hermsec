(function () {
  "use strict";

  const R = HERMSEC_REPORT;
  const adjMap = Object.fromEntries(R.adjudications.map((a) => [a.findingId, a]));

  const TABS = [
    { id: "pipeline", label: "Pipeline", panel: "panel-pipeline", count: R.scanners.length },
    { id: "findings", label: "Findings", panel: "panel-findings", count: R.summary.totalFindings },
    { id: "adjudication", label: "Adjudication", panel: "panel-adjudication", count: R.adjudications.length },
    { id: "threat", label: "Threat Model", panel: "panel-threat" },
    { id: "intel", label: "Intel", panel: "panel-intel", count: R.intelligence.length },
    { id: "fixplan", label: "Fix Plan", panel: "panel-fixplan" },
    { id: "appendix", label: "Appendix", panel: "panel-appendix" }
  ];

  let activeFilters = { severity: "all", category: "all", tool: "all", confidence: "all", search: "" };
  let expandedFindings = new Set();
  let animationsEnabled = false;

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
      "probably false positive": "fp",
      "best-practice recommendation": "practice"
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

  function showToast(msg) {
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("visible");
    setTimeout(() => el.classList.remove("visible"), 2200);
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).then(
      () => showToast("Copied to clipboard"),
      () => showToast("Copy failed")
    );
  }

  function staggerHeader() {
    if (!animationsEnabled) return;
    document.querySelectorAll(".header-reveal > .reveal-item").forEach((el, i) => {
      el.style.animationDelay = `${i * 90}ms`;
    });
  }

  function updateTabIndicator(tabId) {
    const btn = document.getElementById(`tab-${tabId}`);
    const indicator = document.getElementById("tab-indicator");
    if (!btn || !indicator) return;
    indicator.style.width = `${btn.offsetWidth}px`;
    indicator.style.transform = `translateX(${btn.offsetLeft}px)`;
  }

  function staggerPanel(tabId) {
    if (!animationsEnabled) return;
    const panel = document.getElementById(TABS.find((t) => t.id === tabId)?.panel || "");
    if (!panel) return;
    panel.querySelectorAll(".reveal-stagger > .reveal-item").forEach((el, i) => {
      el.style.animationDelay = `${i * 80}ms`;
    });
  }

  function renderHeader() {
    const s = R.summary;
    const scan = R.scan;
    const p = R.posture;

    const sevTotal = s.critical + s.high + s.medium + s.low + s.info || 1;
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

    const secondaryTooltip = [
      `Medium: ${s.medium}`,
      `Low: ${s.low}`,
      `Info: ${s.info}`,
      `Confirmed CVEs: ${s.confirmedCves}`,
      `Known exploited: ${s.knownExploited}`,
      `Scanner failures: ${s.scannerFailures}`
    ].join(" · ");

    const primaryChips = [
      { label: "Critical", value: s.critical, cls: "critical" },
      { label: "High", value: s.high, cls: "high" },
      { label: "Secrets", value: s.secrets, cls: "alert" },
      { label: "Fix now", value: R.fixPlan.fixNow.length, cls: "accent" }
    ]
      .map(
        (c) =>
          `<span class="metric-chip ${c.cls}"><strong>${c.value}</strong> ${esc(c.label)}</span>`
      )
      .join("");

    const commitShort =
      scan.gitCommit && scan.gitCommit.length > 7 ? scan.gitCommit.slice(0, 7) : scan.gitCommit;
    const metaSummary = `${esc(scan.gitBranch)} · ${esc(commitShort)} · ${esc(scan.scanId)} · ${esc(scan.duration)}`;

    const assistLabel = R.assist?.label || scan.assistModeLabel || "Scanner + model summary";

    document.getElementById("report-header").innerHTML = `
      <div class="header-inner">
        <div class="header-row header-row-main">
          <div class="brand brand-compact">
            <div class="brand-text">
              <h1>Security Report</h1>
              <p>${esc(scan.projectName)}</p>
            </div>
          </div>

          <div class="bezel bezel-verdict-compact reveal-item reveal-blur">
            <div class="bezel-inner verdict-inline posture-${esc(p.class)}">
              <span class="posture-pill">${esc(p.grade)}</span>
              <div class="verdict-headline">
                <h2 title="${esc(p.detail)}">${esc(p.headline)}</h2>
              </div>
              <div class="verdict-meta-pills">
                <span class="header-pill"><strong>${R.fixPlan.fixNow.length}</strong> fix now</span>
                <span class="header-pill">${esc(scan.duration)}</span>
                <span class="header-pill">${esc(assistLabel)}</span>
              </div>
            </div>
          </div>

          <div class="header-toolbar">
            <div class="header-actions">
              <button class="btn btn-sm" id="btn-theme" type="button" title="Toggle theme">Theme</button>
              <button class="btn btn-sm btn-primary" id="btn-print" type="button">
                <span>Print / Export</span>
                <span class="btn-icon-ring" aria-hidden="true">\u2197</span>
              </button>
            </div>
          </div>
        </div>

        <div class="header-reveal">
        <div class="header-row header-row-metrics reveal-item">
          <div class="severity-bar-wrap severity-bar-compact">
            <div class="severity-bar">${sevSegments}</div>
          </div>
          <div class="metric-chips">
            ${primaryChips}
            <span class="metric-chip metric-chip-total" title="${esc(secondaryTooltip)}"><strong>${s.totalFindings}</strong> total</span>
          </div>
        </div>

        <details class="meta-disclosure reveal-item">
          <summary class="meta-disclosure-summary">
            <span class="meta-disclosure-label">Scan details</span>
            <span class="meta-disclosure-preview">${metaSummary}</span>
          </summary>
          <div class="meta-strip meta-strip-expanded">
            <div class="meta-item"><span>Path</span><code>${esc(scan.projectPath)}</code></div>
            <div class="meta-item"><span>Scan ID</span><code>${esc(scan.scanId)}</code></div>
            <div class="meta-item"><span>Branch</span><code>${esc(scan.gitBranch)}</code></div>
            <div class="meta-item"><span>Commit</span><code>${esc(scan.gitCommit)}</code></div>
            <div class="meta-item"><span>Dirty tree</span><span>${scan.dirtyWorkingTree ? "Yes" : "No"}</span></div>
            <div class="meta-item"><span>Assist mode</span><span>${esc(assistLabel)}</span></div>
            <div class="meta-item"><span>Started</span><span>${formatDate(scan.startedAt)}</span></div>
            <div class="meta-item"><span>Finished</span><span>${formatDate(scan.finishedAt)}</span></div>
            <div class="meta-item"><span>Report</span><span>${formatDate(scan.reportGeneratedAt)}</span></div>
          </div>
        </details>
        </div>
      </div>`;
  }

  function renderTabs() {
    const indicator = `<div class="tab-indicator" id="tab-indicator" aria-hidden="true"></div>`;
    document.getElementById("tab-nav-inner").innerHTML =
      indicator +
      TABS.map(
        (t) => `
      <button class="tab-btn" id="tab-${t.id}" data-tab="${t.id}" type="button">
        ${esc(t.label)}${t.count != null ? `<span class="tab-count">${t.count}</span>` : ""}
      </button>`
      ).join("");
  }

  function renderPipeline() {
    const items = R.scanners
      .map(
        (s) => `
      <li class="pipeline-item reveal-item">
        <div class="pipeline-status-icon ${esc(s.status)}" aria-label="${esc(s.status)}">${statusIcon(s.status)}</div>
        <div>
          <div class="pipeline-tool-name">${esc(s.name)}</div>
          <div class="pipeline-message">${esc(s.message)}</div>
        </div>
        <div class="pipeline-meta">
          <span class="findings-count">${s.findings} finding${s.findings !== 1 ? "s" : ""}</span>
          <span>${esc(s.duration)}</span>
        </div>
      </li>`
      )
      .join("");
    const assist = R.assist || {};
    const topGroups = (assist.groups || []).slice(0, 3);
    const assistGroups =
      topGroups.length > 0
        ? topGroups
            .map(
              (group) => `
        <div class="assist-mini-group">
          <div>
            <strong>${esc(group.title)}</strong>
            <span>${esc((group.scanners || []).join(" + ") || "Scanner evidence")}</span>
          </div>
          <span class="badge badge-${esc(group.merged ? "confirmed" : "info")}">${esc(group.merged ? "merged" : "single")}</span>
        </div>`
            )
            .join("")
        : `<div class="assist-mini-group"><div><strong>No merge groups yet</strong><span>Hermsec will populate this after scanner findings are available.</span></div></div>`;
    const assistCard = `
      <div class="assist-mode-card reveal-item">
        <div class="assist-mode-copy">
          <span class="section-eyebrow">Assist mode</span>
          <h3>${esc(assist.label || R.scan.assistModeLabel || "Scanner + model summary")}</h3>
          <p>${esc(assist.summary?.note || "Scanner output remains authoritative; the model can only support scanner-backed evidence.")}</p>
        </div>
        <div class="assist-mode-stats">
          <div><strong>${assist.summary?.groups ?? 0}</strong><span>groups</span></div>
          <div><strong>${assist.summary?.mergedGroups ?? 0}</strong><span>merged</span></div>
          <div><strong>${assist.matchingPairs?.length ?? 0}</strong><span>pairs</span></div>
        </div>
        <div class="assist-mini-list">${assistGroups}</div>
      </div>`;

    document.getElementById("panel-pipeline").innerHTML = `
      <h2 class="section-title">Scanner pipeline</h2>
      <p class="section-desc">Status and output from each tool in the Hermsec scan pipeline.</p>
      <div class="bezel bezel-panel">
        <div class="bezel-inner">
          ${assistCard}
          <ul class="pipeline-list reveal-stagger">${items}</ul>
        </div>
      </div>`;
    document.getElementById("panel-pipeline").dataset.printTitle = "Scanner Pipeline";
  }

  function getFilteredFindings() {
    return R.findings.filter((f) => {
      if (activeFilters.severity !== "all" && f.severity !== activeFilters.severity) return false;
      if (activeFilters.category !== "all" && f.category !== activeFilters.category) return false;
      if (activeFilters.tool !== "all" && f.tool !== activeFilters.tool) return false;
      if (activeFilters.confidence !== "all" && f.confidence !== activeFilters.confidence) return false;
      if (activeFilters.search) {
        const q = activeFilters.search.toLowerCase();
        const hay = [f.id, f.title, f.file, f.tool, f.category, f.description].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function renderFindingCard(f) {
    const adj = adjMap[f.id];
    const ids = [...f.cve, ...f.ghsa, ...f.osv];
    const expanded = expandedFindings.has(f.id);

    const tags = [
      ...f.cwe.map((c) => `<span class="tag">${esc(c)}</span>`),
      ...ids.map((id) => `<span class="tag">${esc(id)}</span>`),
      f.package ? `<span class="tag">${esc(f.package)}@${esc(f.version || "?")}</span>` : ""
    ].join("");

    const adjBlock = adj
      ? `
      <div class="agent-inline">
        <h4>Agent adjudication</h4>
        ${verdictBadge(adj.verdict)}
        <p style="margin-top:0.5rem;font-size:0.82rem;color:var(--text-secondary)">${esc(adj.reasoning)}</p>
        <div class="adj-grid" style="margin-top:0.5rem">
          <div class="adj-field"><label>Priority</label><p>${esc(adj.priority)}</p></div>
          <div class="adj-field"><label>Fix first</label><p>${esc(adj.fixFirst)}</p></div>
          <div class="adj-field"><label>Trust boundary</label><p>${esc(adj.trustBoundary)}</p></div>
        </div>
      </div>`
      : "";

    const refs =
      f.references.length > 0
        ? `<div class="finding-section"><h4>References</h4><p>${f.references.map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join("<br>")}</p></div>`
        : "";

    return `
      <article class="finding-card reveal-item bezel bezel-card ${expanded ? "expanded" : ""}" data-severity="${esc(f.severity)}" data-id="${esc(f.id)}">
        <div class="bezel-inner finding-card-inner">
        <div class="finding-header" data-toggle="${esc(f.id)}">
          <div>
            <div class="finding-title-row">
              <span class="finding-id">${esc(f.id)}</span>
              ${badge(f.severity)}
              <span class="badge badge-info" style="text-transform:none;letter-spacing:0">${esc(f.confidence)}</span>
              ${adj ? verdictBadge(adj.verdict) : ""}
            </div>
            <div class="finding-title">${esc(f.title)}</div>
            <div class="finding-meta-row">
              <span>${esc(f.category)}</span>
              <span>${esc(f.tool)}</span>
              <span><code>${esc(f.file)}${f.line ? ":" + f.line : ""}</code></span>
            </div>
          </div>
          <span class="finding-chevron" aria-hidden="true">\u25BC</span>
        </div>
        <div class="finding-body">
          <div class="finding-section"><h4>Evidence</h4><pre class="evidence-block">${esc(f.evidence)}</pre></div>
          <div class="finding-section"><h4>Description</h4><p>${esc(f.description)}</p></div>
          <div class="finding-section"><h4>Impact</h4><p>${esc(f.impact)}</p></div>
          <div class="finding-section"><h4>Remediation</h4><p>${esc(f.remediation)}</p></div>
          ${tags ? `<div class="finding-section"><h4>Identifiers</h4><div class="finding-tags">${tags}</div></div>` : ""}
          <div class="finding-section"><h4>Fingerprint</h4><p><code>${esc(f.fingerprint)}</code></p></div>
          ${refs}
          ${adjBlock}
          <div class="finding-actions">
            <button class="btn btn-sm" type="button" data-copy-id="${esc(f.id)}">Copy ID</button>
            <button class="btn btn-sm" type="button" data-open-file="${esc(f.file)}">Open file path</button>
          </div>
        </div>
        </div>
      </article>`;
  }

  function renderFindings() {
    const severities = ["all", "critical", "high", "medium", "low", "info"];
    const categories = ["all", ...new Set(R.findings.map((f) => f.category))];
    const tools = ["all", ...new Set(R.findings.map((f) => f.tool))];
    const confidences = ["all", ...new Set(R.findings.map((f) => f.confidence))];

    function chips(name, values) {
      return values
        .map(
          (v) =>
            `<button class="chip ${activeFilters[name] === v ? "active" : ""}" data-filter="${name}" data-value="${esc(v)}" type="button">${esc(v === "all" ? "All" : v)}</button>`
        )
        .join("");
    }

    const filtered = getFilteredFindings();
    const list =
      filtered.length > 0
        ? filtered.map(renderFindingCard).join("")
        : `<div class="empty-state"><strong>No findings match filters</strong><p>Try clearing filters or broadening your search.</p></div>`;

    document.getElementById("panel-findings").innerHTML = `
      <h2 class="section-title">Findings</h2>
      <p class="section-desc">Filter and expand individual findings. Agent verdicts appear inline when available.</p>
      <div class="findings-toolbar">
        <div class="filter-chips">${chips("severity", severities)}</div>
        <div class="filter-chips">${chips("category", categories)}</div>
        <div class="filter-chips">${chips("tool", tools)}</div>
        <div class="filter-chips">${chips("confidence", confidences)}</div>
        <input class="search-input" type="search" id="findings-search" placeholder="Search findings..." value="${esc(activeFilters.search)}">
        <div class="toolbar-actions">
          <button class="btn btn-sm" id="btn-expand-all" type="button">Expand all</button>
          <button class="btn btn-sm" id="btn-collapse-all" type="button">Collapse all</button>
        </div>
        <div class="findings-count-label">Showing ${filtered.length} of ${R.findings.length} findings</div>
      </div>
      <div class="findings-list reveal-stagger" id="findings-list">${list}</div>`;
    document.getElementById("panel-findings").dataset.printTitle = "Findings";
  }

  function renderAdjudication() {
    const assistGroups = R.assist?.groups || [];
    const mergeMap =
      assistGroups.length > 0
        ? `
      <div class="assist-merge-list reveal-stagger">
        ${assistGroups
          .slice(0, 8)
          .map(
            (group) => `
        <article class="assist-merge-card reveal-item bezel bezel-card">
          <div class="bezel-inner assist-merge-card-inner">
            <div class="assist-merge-header">
              <div>
                <span class="finding-id">${esc(group.id)}</span>
                <h3>${esc(group.title)}</h3>
              </div>
              <span class="badge badge-${esc(group.merged ? "confirmed" : "info")}">${esc(group.confidence)}</span>
            </div>
            <div class="assist-evidence-row">
              <span>${esc((group.scanners || []).join(" + ") || "scanner evidence")}</span>
              <span>${esc((group.locations || []).slice(0, 2).join(", ") || "No file location")}</span>
              <span>${esc((group.findingIds || []).join(", "))}</span>
            </div>
            <p>${esc(group.modelSupport || "Model support is limited to this scanner-backed group.")}</p>
          </div>
        </article>`
          )
          .join("")}
      </div>`
        : `<div class="empty-state"><strong>No scanner merge map</strong><p>This report has no assistant merge artifact yet.</p></div>`;
    const cards = R.adjudications
      .map((a) => {
        const f = R.findings.find((x) => x.id === a.findingId);
        return `
        <article class="adj-card reveal-item bezel bezel-card">
          <div class="bezel-inner adj-card-inner">
          <div class="adj-card-header">
            <span class="finding-id">${esc(a.findingId)}</span>
            ${verdictBadge(a.verdict)}
            ${f ? badge(f.severity) : ""}
          </div>
          <p style="margin:0;font-size:0.875rem;font-weight:500">${f ? esc(f.title) : ""}</p>
          <p style="margin:0.5rem 0 0;font-size:0.82rem;color:var(--text-secondary)">${esc(a.reasoning)}</p>
          <div class="adj-grid">
            <div class="adj-field"><label>Priority</label><p>${esc(a.priority)}</p></div>
            <div class="adj-field"><label>What to fix first</label><p>${esc(a.fixFirst)}</p></div>
            <div class="adj-field"><label>Trust boundary</label><p>${esc(a.trustBoundary)}</p></div>
            <div class="adj-field"><label>Assumptions</label><p>${esc(a.assumptions)}</p></div>
          </div>
          </div>
        </article>`;
      })
      .join("");

    document.getElementById("panel-adjudication").innerHTML = `
      <h2 class="section-title">Agent adjudication</h2>
      <p class="section-desc">Model review of scanner evidence. Does not replace scanner output or manual verification.</p>
      <h3 class="subsection-title">Scanner-confirmed merge map</h3>
      ${mergeMap}
      <h3 class="subsection-title">Finding verdicts</h3>
      <div class="adj-list reveal-stagger">${cards}</div>`;
    document.getElementById("panel-adjudication").dataset.printTitle = "Agent Adjudication";
  }

  function renderThreatModel() {
    const tm = R.threatModel;
    function block(title, items) {
      return `
        <div class="threat-block reveal-item bezel bezel-card">
          <div class="bezel-inner threat-block-inner">
            <h3>${esc(title)}</h3>
            <ul>${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>
          </div>
        </div>`;
    }

    document.getElementById("panel-threat").innerHTML = `
      <h2 class="section-title">Threat model</h2>
      <p class="section-desc">Concise AppSec view of assets, boundaries, and abuse paths for this workspace.</p>
      <div class="threat-grid reveal-stagger">
        ${block("Assets", tm.assets)}
        ${block("Entry points", tm.entryPoints)}
        ${block("Trust boundaries", tm.trustBoundaries)}
        ${block("Attacker capabilities", tm.attackerCapabilities)}
        ${block("Abuse paths", tm.abusePaths)}
        ${block("Mitigations", tm.mitigations)}
        ${block("Unresolved assumptions", tm.unresolvedAssumptions)}
      </div>`;
    document.getElementById("panel-threat").dataset.printTitle = "Threat Model";
  }

  function renderIntel() {
    const cards = R.intelligence
      .map(
        (i) => `
      <article class="intel-card reveal-item bezel bezel-card ${i.knownExploited ? "kev" : ""}">
        <div class="bezel-inner intel-card-inner">
        <div>
          <div class="intel-title">${esc(i.title)}</div>
          <div class="intel-meta">
            <span>${esc(i.source)}</span>
            ${badge(i.severity)}
            ${i.knownExploited ? `<span class="badge badge-critical">Known Exploited</span>` : ""}
            <span>${esc(i.ecosystem)} / ${esc(i.package)}</span>
            <span>CVE ${esc(i.cve)}</span>
            <span>Published ${esc(i.published)}</span>
          </div>
          <p class="intel-why"><strong>Why it matters:</strong> ${esc(i.whyItMatters)}</p>
        </div>
        <a class="intel-link" href="${esc(i.url)}" target="_blank" rel="noopener">View advisory<span class="link-arrow" aria-hidden="true">\u2197</span></a>
        </div>
      </article>`
      )
      .join("");

    document.getElementById("panel-intel").innerHTML = `
      <h2 class="section-title">Vulnerability intelligence</h2>
      <p class="section-desc">Online intelligence cross-referenced against project dependencies and findings.</p>
      <div class="intel-list reveal-stagger">${cards}</div>`;
    document.getElementById("panel-intel").dataset.printTitle = "Vulnerability Intelligence";
  }

  function renderFixPlanColumn(title, cls, items) {
    const body =
      items.length > 0
        ? items
            .map(
              (item) => `
          <div class="fixplan-item">
            <h4>${esc(item.title)}</h4>
            <p>IDs: ${item.findingIds.map((id) => esc(id)).join(", ") || "N/A"}</p>
            <p>Owner: ${esc(item.owner)} | Effort: ${esc(item.effort)}</p>
            <p>Validate: ${esc(item.validation)}</p>
            <code>${esc(item.command)}</code>
          </div>`
            )
            .join("")
        : `<div class="empty-state" style="padding:1.5rem"><p>No items</p></div>`;

    return `
      <div class="fixplan-col reveal-item bezel bezel-card">
        <div class="bezel-inner fixplan-col-inner">
          <div class="fixplan-col-header ${cls}">${esc(title)}</div>
          <div class="fixplan-items">${body}</div>
        </div>
      </div>`;
  }

  function renderFixPlan() {
    const fp = R.fixPlan;
    document.getElementById("panel-fixplan").innerHTML = `
      <h2 class="section-title">Recommended fix plan</h2>
      <p class="section-desc">Prioritized remediation grouped by urgency. Each action links to finding IDs and validation steps.</p>
      <div class="fixplan-grid reveal-stagger">
        ${renderFixPlanColumn("Fix now", "fix-now", fp.fixNow)}
        ${renderFixPlanColumn("Fix this week", "fix-week", fp.fixThisWeek)}
        ${renderFixPlanColumn("Monitor", "monitor", fp.monitor)}
        ${renderFixPlanColumn("Needs context", "needs-context", fp.needsContext)}
      </div>`;
    document.getElementById("panel-fixplan").dataset.printTitle = "Fix Plan";
  }

  function renderAppendix() {
    const ev = R.evidence;
    const rawBlocks = ev.rawOutputs
      .map(
        (o) => `
      <div class="raw-output">
        <div class="raw-output-header"><span>${esc(o.scanner)}</span></div>
        <pre>${esc(o.content)}</pre>
      </div>`
      )
      .join("");

    const failed = ev.failedScanners
      .map((f) => `<li><strong>${esc(f.name)}</strong>: ${esc(f.reason)}</li>`)
      .join("");

    const paths = ev.artifactPaths.map((p) => `<li><code>${esc(p)}</code></li>`).join("");
    const limits = ev.limitations.map((l) => `<li>${esc(l)}</li>`).join("");

    document.getElementById("panel-appendix").innerHTML = `
      <h2 class="section-title">Evidence appendix</h2>
      <p class="section-desc">Raw scanner output, limitations, and artifact locations.</p>
      <div class="notice">${esc(ev.redactionNote)}</div>

      <div class="appendix-section">
        <h3>Limitations</h3>
        <ul style="font-size:0.82rem;color:var(--text-secondary);padding-left:1.25rem">${limits}</ul>
      </div>

      <div class="appendix-section">
        <h3>Failed scanners</h3>
        <ul style="font-size:0.82rem;color:var(--text-secondary);padding-left:1.25rem">${failed || "<li>None</li>"}</ul>
      </div>

      <div class="appendix-section">
        <h3>Report artifacts</h3>
        <ul style="font-size:0.78rem;padding-left:1.25rem">${paths}</ul>
      </div>

      <div class="appendix-section">
        <h3>Raw scanner output</h3>
        ${rawBlocks}
      </div>`;
    document.getElementById("panel-appendix").dataset.printTitle = "Evidence Appendix";
  }

  function renderFooter() {
    document.getElementById("report-footer").textContent =
      `Generated by Hermsec | Scan ${R.scan.scanId} | Interactive dashboard report`;
  }

  function switchTab(tabId) {
    TABS.forEach((t) => {
      document.getElementById(`tab-${t.id}`)?.classList.toggle("active", t.id === tabId);
      document.getElementById(t.panel)?.classList.toggle("active", t.id === tabId);
    });
    history.replaceState(null, "", `#${tabId}`);
    requestAnimationFrame(() => {
      updateTabIndicator(tabId);
      staggerPanel(tabId);
    });
  }

  function initTheme() {
    document.documentElement.dataset.theme = "dark";
  }

  function toggleTheme() {
    document.documentElement.dataset.theme = "dark";
    showToast("Dashboard uses the Hermsec app theme.");
  }

  function bindEvents() {
    document.getElementById("tab-nav-inner").addEventListener("click", (e) => {
      const btn = e.target.closest(".tab-btn");
      if (btn) switchTab(btn.dataset.tab);
    });

    document.getElementById("btn-theme")?.addEventListener("click", toggleTheme);
    document.getElementById("btn-print")?.addEventListener("click", () => window.print());

    document.getElementById("report-main")?.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (chip) {
        activeFilters[chip.dataset.filter] = chip.dataset.value;
        renderFindings();
        bindFindingEvents();
        return;
      }

      const toggle = e.target.closest("[data-toggle]");
      if (toggle) {
        const id = toggle.dataset.toggle;
        if (expandedFindings.has(id)) expandedFindings.delete(id);
        else expandedFindings.add(id);
        renderFindings();
        bindFindingEvents();
        return;
      }

      const copyBtn = e.target.closest("[data-copy-id]");
      if (copyBtn) {
        copyText(copyBtn.dataset.copyId);
        return;
      }

      const openBtn = e.target.closest("[data-open-file]");
      if (openBtn) {
        const path = R.scan.projectPath + "\\" + openBtn.dataset.openFile.replace(/\//g, "\\");
        copyText(path);
        showToast("File path copied (paste in editor)");
      }
    });

    document.getElementById("report-main")?.addEventListener("input", (e) => {
      if (e.target.id === "findings-search") {
        activeFilters.search = e.target.value;
        renderFindings();
        bindFindingEvents();
      }
    });

    window.addEventListener("resize", () => {
      const active = TABS.find((t) => document.getElementById(t.panel)?.classList.contains("active"));
      if (active) updateTabIndicator(active.id);
    });
  }

  function bindFindingEvents() {
    document.getElementById("btn-expand-all")?.addEventListener("click", () => {
      getFilteredFindings().forEach((f) => expandedFindings.add(f.id));
      renderFindings();
      bindFindingEvents();
    });
    document.getElementById("btn-collapse-all")?.addEventListener("click", () => {
      expandedFindings.clear();
      renderFindings();
      bindFindingEvents();
    });
  }

  function init() {
    initTheme();
    renderHeader();
    renderTabs();
    renderPipeline();
    renderFindings();
    renderAdjudication();
    renderThreatModel();
    renderIntel();
    renderFixPlan();
    renderAppendix();
    renderFooter();
    bindEvents();
    bindFindingEvents();

    const hash = location.hash.replace("#", "");
    const initialTab = TABS.some((t) => t.id === hash) ? hash : "pipeline";
    switchTab(initialTab);

    requestAnimationFrame(() => {
      updateTabIndicator(initialTab);
      requestAnimationFrame(() => {
        animationsEnabled = true;
        document.getElementById("report")?.classList.add("report--animated");
        staggerHeader();
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
