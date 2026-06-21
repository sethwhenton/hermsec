import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import type {
  ConverseReportRequest,
  ConverseReportResult,
  DashboardBundleRequest,
  DashboardBundleResult,
  ExplainReportRequest,
  ExplainReportResult,
  LatestReportResult,
  OpenArtifactRequest,
  OpenArtifactResult,
  ReportControlResult,
} from "../renderer/src/types/reports";
import type { ProviderConfig } from "../renderer/src/types/settings";
import { redactPrivacyText, redactPrivacyValue } from "./privacy";
import { dashboardBundle } from "./reportArtifacts";
import { openReportLocation } from "./scan";
import { readSettings } from "./store";

type Finding = {
  title?: string;
  severity?: string;
  category?: string;
  confidence?: string;
  tool?: string;
  ruleId?: string;
  cwe?: string[];
  description?: string;
  evidence?: string;
  remediation?: string;
  location?: {
    file?: string;
    startLine?: number;
  };
};

type SummaryFile = {
  generatedAt?: string;
  scanId?: string;
  summary?: Record<string, unknown>;
  target?: {
    displayName?: string;
    value?: string;
  };
  workspaceName?: string;
};

type ReportIntent = "fixes" | "severity" | "secrets" | "locations" | "status" | "fixPrompt" | "summary";

interface BuiltReportAnswer {
  message: string;
  intent: ReportIntent;
  copyLabel?: string;
  copyText?: string;
  promptFilePath?: string;
}

interface ReportCandidate {
  reportDir: string;
  generatedAt: string;
  projectPath?: string;
  mtimeMs: number;
}

let activeConversationController: AbortController | null = null;

export function explainReport(request: ExplainReportRequest): ExplainReportResult {
  try {
    const reportPath = path.resolve(request.reportPath);
    if (!existsSync(reportPath)) {
      return { ok: false, message: `Report not found: ${reportPath}`, reportPath };
    }

    const reportDir = path.dirname(reportPath);
    const summary = readJson<SummaryFile>(path.join(reportDir, "summary.json"));
    const findings = normalizeFindings(readJson<unknown>(path.join(reportDir, "findings.json")));
    const question = request.question.toLowerCase();
    const answer = buildReportAnswer({
      reportPath,
      summary,
      findings,
      intent: classifyReportIntent(question),
      question,
      previousPrompt: request.previousPrompt,
    });
    const output = readSettings().general.privacyMode
      ? privacyProtectReportAnswer(answer, summary?.target?.value)
      : answer;

    return {
      ok: true,
      message: output.message,
      reportPath,
      intent: output.intent,
      ...(output.copyLabel ? { copyLabel: output.copyLabel } : {}),
      ...(output.copyText ? { copyText: output.copyText } : {}),
      ...(output.promptFilePath ? { promptFilePath: output.promptFilePath } : {}),
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not explain the report.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function converseReport(request: ConverseReportRequest): Promise<ConverseReportResult> {
  try {
    const privacyMode = readSettings().general.privacyMode;
    const resolvedReportPath = resolveConversationReportPath(request);
    let reportPath: string | undefined;
    let evidence: ConversationEvidence;

    if (resolvedReportPath) {
      reportPath = path.resolve(resolvedReportPath);
      if (!existsSync(reportPath)) {
        return {
          ok: false,
          message: `Report not found: ${reportPath}`,
          reportPath,
        };
      }

      const reportDir = path.dirname(reportPath);
      const summary = readJson<SummaryFile>(path.join(reportDir, "summary.json"));
      const findings = normalizeFindings(readJson<unknown>(path.join(reportDir, "findings.json")));
      evidence = buildConversationEvidence({ reportPath, summary, findings });
    } else {
      evidence = buildGeneralConversationEvidence(request.projectPath);
    }

    const projectRoot = evidence.projectRoot ?? request.projectPath;
    const modelEvidence = privacyMode ? redactPrivacyValue(evidence, projectRoot) : evidence;
    const modelMessage = await callConversationModel({
      question: request.question,
      history: request.history ?? [],
      evidence: modelEvidence,
      privacyMode,
      projectRoot,
    });

    if (modelMessage) {
      return {
        ok: true,
        message: modelMessage.message,
        ...(reportPath ? { reportPath } : {}),
        usedModel: true,
        modelId: modelMessage.modelId,
      };
    }

    return {
      ok: true,
      message: privacyMode
        ? redactPrivacyText(buildConversationalFallback(request.question, evidence), projectRoot)
        : buildConversationalFallback(request.question, evidence),
      ...(reportPath ? { reportPath } : {}),
      usedModel: false,
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not continue the report conversation.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function cancelActiveReportAction(): ReportControlResult {
  if (!activeConversationController) {
    return { ok: false, message: "No report action is currently running." };
  }

  activeConversationController.abort();
  activeConversationController = null;
  return { ok: true, message: "Report action stop requested." };
}

export function latestReport(projectPath?: string): LatestReportResult {
  try {
    const settings = readSettings();
    const root = settings.defaultReportDir;
    if (!existsSync(root)) {
      return { ok: false, message: `Report directory was not found: ${root}` };
    }

    const normalizedProject = projectPath ? normalizePath(projectPath) : undefined;
    const candidate = collectReportCandidates(root)
      .filter((item) => (normalizedProject ? normalizePath(item.projectPath ?? "") === normalizedProject : true))
      .sort((a, b) => {
        const time = Date.parse(b.generatedAt) - Date.parse(a.generatedAt);
        return Number.isFinite(time) && time !== 0 ? time : b.mtimeMs - a.mtimeMs;
      })[0];

    if (!candidate) {
      return { ok: false, message: "No report has been generated for this project yet.", projectPath };
    }

    return candidateToLatest(candidate, projectPath);
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not locate the latest report.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function getDashboardBundle(request: DashboardBundleRequest): DashboardBundleResult {
  return dashboardBundle(request.reportPathOrDir);
}

export async function openArtifact(request: OpenArtifactRequest): Promise<OpenArtifactResult> {
  return openReportLocation({ path: request.path });
}

function readJson<T>(filePath: string): T | null {
  if (!existsSync(filePath)) return null;
  return JSON.parse(readFileSync(filePath, "utf8")) as T;
}

function collectReportCandidates(root: string): ReportCandidate[] {
  const candidates: ReportCandidate[] = [];
  walkReportDirs(path.resolve(root), candidates, 0);
  return candidates;
}

function walkReportDirs(current: string, candidates: ReportCandidate[], depth: number): void {
  if (depth > 8 || candidates.length > 2000) return;

  const reportDocumentPath = path.join(current, "report-document.json");
  const summaryPath = path.join(current, "summary.json");
  if (existsSync(reportDocumentPath) || existsSync(summaryPath)) {
    const document = readJson<SummaryFile>(reportDocumentPath) ?? readJson<SummaryFile>(summaryPath);
    let mtimeMs = Date.now();
    try {
      mtimeMs = statSync(existsSync(reportDocumentPath) ? reportDocumentPath : summaryPath).mtimeMs;
    } catch {
      // Keep a stable fallback if the file disappears between checks.
    }
    candidates.push({
      reportDir: current,
      generatedAt: document?.generatedAt ?? new Date(mtimeMs).toISOString(),
      projectPath: document?.target?.value,
      mtimeMs,
    });
  }

  let entries;
  try {
    entries = readdirSync(current, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === "dashboard" || entry.name === "onepager") continue;
    walkReportDirs(path.join(current, entry.name), candidates, depth + 1);
  }
}

function candidateToLatest(candidate: ReportCandidate, projectPath?: string): LatestReportResult {
  const reportDir = candidate.reportDir;
  const htmlPath = path.join(reportDir, "report.html");
  const dashboardHtmlPath = path.join(reportDir, "dashboard", "index.html");
  const onepagerHtmlPath = path.join(reportDir, "onepager", "index.html");
  const onepagerPdfPath = path.join(reportDir, "onepager", "report.pdf");
  const projectState = readJson<LatestReportResult["projectState"]>(path.join(reportDir, "project-state.json"));
  return {
    ok: true,
    projectPath: projectPath ?? candidate.projectPath,
    reportDir,
    ...(existsSync(htmlPath) ? { htmlPath } : {}),
    ...(existsSync(dashboardHtmlPath) ? { dashboardHtmlPath } : {}),
    ...(existsSync(onepagerHtmlPath) ? { onepagerHtmlPath } : {}),
    ...(existsSync(onepagerPdfPath) ? { onepagerPdfPath } : {}),
    generatedAt: candidate.generatedAt,
    ...(projectState ? { projectState } : {}),
  };
}

function normalizeFindings(value: unknown): Finding[] {
  if (Array.isArray(value)) return value as Finding[];
  if (value && typeof value === "object" && Array.isArray((value as { findings?: unknown }).findings)) {
    return (value as { findings: Finding[] }).findings;
  }
  return [];
}

function classifyReportIntent(question: string): ReportIntent {
  if (/\b(have you scanned|did you scan|already scanned|latest scan|when did|has this been scanned)\b/.test(question)) return "status";
  if (/\b(prompt|copy prompt|another agent|coding agent|fixing agent|send .*agent|agent .*fix|revise|revision|rewrite|another version|update it|break it down|phases?)\b/.test(question)) return "fixPrompt";
  if (/\b(fix|remed|patch|solve|resolve|how do i)\b/.test(question)) return "fixes";
  if (/\b(where|file|line|code|source|location|show me|point me)\b/.test(question)) return "locations";
  if (/\b(severity|critical|high|medium|low|priorit|risk)\b/.test(question)) return "severity";
  if (/\b(secret|token|key|credential)\b/.test(question)) return "secrets";
  return "summary";
}

function buildReportAnswer({
  reportPath,
  summary,
  findings,
  intent,
  question,
  previousPrompt,
}: {
  reportPath: string;
  summary: SummaryFile | null;
  findings: Finding[];
  intent: ReportIntent;
  question: string;
  previousPrompt?: string;
}): BuiltReportAnswer {
  const counts = normalizeCounts(summary?.summary, findings);
  const targetName =
    summary?.target?.displayName ?? summary?.workspaceName ?? path.basename(path.dirname(path.dirname(reportPath)));
  const projectRoot = summary?.target?.value;
  const topFindings = sortFindings(findings).slice(0, intent === "fixes" ? 5 : 4);
  const scannerFailureText = counts.scannerFailures > 0
    ? ` One scanner reported a failure, so treat this as a strong first pass rather than the final word.`
    : "";

  if (intent === "status") {
    return {
      intent,
      message: [
      `Yes. I have a latest Hermsec scan report for ${targetName}.`,
      `It was generated ${formatReportDate(summary?.generatedAt)} and found ${counts.total} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} info.`,
      `Report file: ${reportPath}`,
      "",
      "You can ask me things like \"what should I fix first?\", \"show me the files and lines\", or \"explain the critical issue\" and I will answer from this report evidence.",
    ].join("\n"),
    };
  }

  if (intent === "fixPrompt") {
    const promptStyle = classifyPromptStyle(question, previousPrompt);
    const prompt = buildFixAgentPrompt({ reportPath, targetName, projectRoot, counts, findings, style: promptStyle });
    const promptFilePath = writePromptArtifact(reportPath, prompt, promptStyle);
    return {
      intent,
      message: [
        promptStyle === "phased"
          ? "Here is a phased scanner-backed prompt you can give to another coding agent."
          : "Here is a scanner-backed prompt you can give to another coding agent to fix the security issues.",
        "I kept it scoped to the latest Hermsec report, with file/line evidence and verification requirements.",
        promptFilePath ? `I also saved this prompt version as a text file:\n${promptFilePath}` : "",
        "",
        "```text",
        prompt,
        "```",
      ].filter(Boolean).join("\n"),
      copyLabel: promptStyle === "phased" ? "Copy phased fix prompt" : "Copy fix prompt",
      copyText: prompt,
      ...(promptFilePath ? { promptFilePath } : {}),
    };
  }

  if (intent === "fixes") {
    return {
      intent,
      message: [
      `For ${targetName}, I would fix these first based on the latest report evidence:`,
      ...topFindings.map((finding, index) => formatFixFinding(finding, index + 1, projectRoot)),
      "",
      `After patching, rerun an Online scan and compare the new report against this one.${scannerFailureText}`,
    ].join("\n"),
    };
  }

  if (intent === "severity") {
    return {
      intent,
      message: [
      `The report for ${targetName} has ${counts.total} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} info.`,
      `Priority order: fix critical code-execution issues first, then exposed secrets, then injection and unsafe dynamic code paths.`,
      ...topFindings.map((finding, index) => formatBriefFinding(finding, index + 1, projectRoot)),
      scannerFailureText.trim(),
    ].filter(Boolean).join("\n"),
    };
  }

  if (intent === "secrets") {
    const secretFindings = findings.filter((finding) => finding.category === "secret" || /secret|token|key/i.test(finding.title ?? ""));
    if (secretFindings.length === 0) {
      return {
        intent,
        message: `I do not see secret findings in the latest report for ${targetName}. Still, rotate any credential that may have been committed and rerun the scan after cleanup.`,
      };
    }
    return {
      intent,
      message: [
      `The latest report found ${secretFindings.length} secret-related issue${secretFindings.length === 1 ? "" : "s"} in ${targetName}.`,
      ...secretFindings.slice(0, 4).map((finding, index) => formatFixFinding(finding, index + 1, projectRoot)),
      "",
      "For secrets, the safe response is remove them from code, rotate the exposed value, and move future values into environment variables or a secret manager.",
    ].join("\n"),
    };
  }

  if (intent === "locations") {
    return {
      intent,
      message: [
      `Here are the main code locations Hermsec found in ${targetName}:`,
      ...topFindings.map((finding, index) => formatLocatedFinding(finding, index + 1, projectRoot)),
      "",
      "These are scanner-backed locations. I can walk through any one of them and suggest a patch strategy before you change code.",
    ].join("\n"),
    };
  }

  return {
    intent,
    message: [
    `Here is the security readout from the latest Hermsec HTML report for ${targetName}:`,
    `It found ${counts.total} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} info. Secrets flagged: ${counts.secrets}.`,
    ...topFindings.map((finding, index) => formatBriefFinding(finding, index + 1, projectRoot)),
    "",
    `The practical next step is to fix the highest-severity executable-code and secret findings, then rerun the Online scan to confirm the report improves.${scannerFailureText}`,
  ].join("\n"),
  };
}

function privacyProtectReportAnswer(answer: BuiltReportAnswer, projectRoot?: string): BuiltReportAnswer {
  return {
    ...answer,
    message: redactPrivacyText(answer.message, projectRoot),
    ...(answer.copyText ? { copyText: redactPrivacyText(answer.copyText, projectRoot) } : {}),
  };
}

interface ConversationEvidenceFinding {
  title: string;
  severity: string;
  category?: string;
  tool?: string;
  ruleId?: string;
  location: string;
  description: string;
  remediation: string;
  code?: string;
}

interface ConversationEvidence {
  reportPath?: string;
  targetName: string;
  projectRoot?: string;
  generatedAt?: string;
  counts: ReturnType<typeof normalizeCounts>;
  findings: ConversationEvidenceFinding[];
  note?: string;
}

function resolveConversationReportPath(request: ConverseReportRequest): string | undefined {
  if (request.reportPath) return request.reportPath;
  const latest = latestReport(request.projectPath);
  return latest.ok ? latest.htmlPath : undefined;
}

function buildConversationEvidence({
  reportPath,
  summary,
  findings,
}: {
  reportPath: string;
  summary: SummaryFile | null;
  findings: Finding[];
}): ConversationEvidence {
  const projectRoot = summary?.target?.value;
  return {
    reportPath,
    targetName: summary?.target?.displayName ?? summary?.workspaceName ?? path.basename(path.dirname(reportPath)),
    ...(projectRoot ? { projectRoot } : {}),
    ...(summary?.generatedAt ? { generatedAt: summary.generatedAt } : {}),
    counts: normalizeCounts(summary?.summary, findings),
    findings: sortFindings(findings).slice(0, 16).map((finding) => ({
      title: finding.title ?? "Security finding",
      severity: finding.severity?.toUpperCase() ?? "INFO",
      ...(finding.category ? { category: finding.category } : {}),
      ...(finding.tool ? { tool: finding.tool } : {}),
      ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
      location: formatLocation(finding) || "Location not recorded",
      description: redactSensitive(finding.description ?? finding.evidence ?? "Hermsec found scanner evidence for this issue."),
      remediation: redactSensitive(finding.remediation ?? "Review the evidence, patch the risky code path, and rerun the scan."),
      ...(sourceLineSnippet(projectRoot, finding) ? { code: sourceLineSnippet(projectRoot, finding) } : {}),
    })),
  };
}

function buildGeneralConversationEvidence(projectPath?: string): ConversationEvidence {
  return {
    targetName: projectPath ? path.basename(projectPath) : "the selected Hermsec project",
    ...(projectPath ? { projectRoot: projectPath } : {}),
    counts: normalizeCounts(undefined, []),
    findings: [],
    note: [
      "No scan report is loaded for this conversation yet.",
      "The assistant may have a normal conversation, answer Hermsec/product/security questions, help configure automations, and suggest running a scan when evidence is needed.",
      "Do not claim scanner findings, file locations, CVEs, or dependency vulnerabilities unless they are provided in evidence.",
    ].join(" "),
  };
}

async function callConversationModel({
  question,
  history,
  evidence,
  privacyMode,
  projectRoot,
}: {
  question: string;
  history: ConverseReportRequest["history"];
  evidence: ConversationEvidence;
  privacyMode: boolean;
  projectRoot?: string;
}): Promise<{ message: string; modelId: string } | null> {
  const modelConfig = resolveModelConfig();
  if (!modelConfig) return null;

  const controller = new AbortController();
  activeConversationController?.abort();
  activeConversationController = controller;
  const timeout = setTimeout(() => controller.abort(), 20_000);
  const messages = [
    {
      role: "system",
      content: [
        "You are Hermsec, a defensive security assistant for repository owners.",
        "Use a formal, concise, direct tone.",
        "Avoid casual greetings, playful language, excessive encouragement, and ultra-friendly chat.",
        "Answer with the minimum context needed to be useful.",
        "For general questions, answer briefly and then state the relevant Hermsec next step if applicable.",
        "Return only the final answer shown to the user.",
        "Never reveal hidden reasoning, chain-of-thought, planning notes, internal checklists, or statements like 'The user is asking...' or 'I need to...'.",
        "Do not narrate how you are deciding what to do. Just answer.",
        "Use only the supplied Hermsec scan evidence for claims about this project's actual vulnerabilities.",
        "Do not invent files, line numbers, CVEs, scanner results, dependencies, or secrets.",
        "If evidence is missing, say what scan or context is needed.",
        "Do not provide exploit playbooks or offensive step-by-step attack instructions.",
        "You may explain risk, show affected files/lines, recommend patches, and help the user decide what to fix first.",
        "You may help plan scan automations, report settings, provider/model settings, and safe remediation workflows.",
        "Hermsec action map:",
        "- Normal chat: answer directly while staying around repository security and Hermsec usage.",
        "- Read scan/report: explain supplied report evidence, findings, affected files, severity, and remediation order.",
        "- Start scan: if the user asks to scan, tell them Hermsec can run the Online scan pipeline; the app router may start it directly.",
        "- Set automation: if the user asks for recurring scans, help gather cadence and exact time; the app router may persist it directly.",
        "- Fix prompt: if the user asks for another coding agent prompt, generate a defensive prompt scoped to the report evidence.",
        "- Prompt revision: if the user asks to update, rewrite, phase, or improve a previous prompt, produce the revised prompt only.",
        "When useful, structure the answer with short sections and compact bullets.",
      ].join("\n"),
    },
    {
      role: "user",
      content: [
        "Hermsec scan evidence packet:",
        JSON.stringify(evidence, null, 2),
      ].join("\n"),
    },
    ...normalizeConversationHistory(history, privacyMode, projectRoot).slice(-modelConfig.historyTurns),
    {
      role: "user",
      content: privacyMode ? redactPrivacyText(question, projectRoot) : redactSensitive(question),
    },
  ];

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (modelConfig.apiKey) {
      headers.Authorization = `Bearer ${modelConfig.apiKey}`;
    }

    const response = await fetch(`${modelConfig.baseUrl}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: modelConfig.modelId,
        temperature: 0.25,
        max_tokens: modelConfig.maxTokens,
        messages,
      }),
      signal: controller.signal,
    });

    if (!response.ok) return null;
    const body = await response.json() as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = body.choices?.[0]?.message?.content?.trim();
    if (!rawContent) return null;
    const content = sanitizeModelAnswer(rawContent, question, evidence, privacyMode, projectRoot);
    if (!content) return null;
    return {
      message: content,
      modelId: modelConfig.modelId,
    };
  } catch {
    return null;
  } finally {
    if (activeConversationController === controller) {
      activeConversationController = null;
    }
    clearTimeout(timeout);
  }
}

function normalizeConversationHistory(
  history: ConverseReportRequest["history"] = [],
  privacyMode = false,
  projectRoot?: string,
) {
  return history
    .filter((message) => message.content.trim())
    .map((message) => ({
      role: message.role,
      content: (privacyMode ? redactPrivacyText(message.content, projectRoot) : redactSensitive(message.content)).slice(0, 2000),
    }));
}

function sanitizeModelAnswer(
  content: string,
  question: string,
  evidence: ConversationEvidence,
  privacyMode: boolean,
  projectRoot?: string,
): string | null {
  const redacted = (privacyMode ? redactPrivacyText(content, projectRoot) : redactSensitive(content)).trim();
  if (!redacted) return null;

  const finalAnswer = extractFinalAnswer(redacted);
  if (looksLikeInternalReasoning(finalAnswer)) {
    return buildReasoningLeakFallback(question, evidence);
  }

  return finalAnswer;
}

function extractFinalAnswer(content: string): string {
  const markers = [
    /(?:^|\n)final answer\s*:\s*/i,
    /(?:^|\n)final\s*:\s*/i,
    /(?:^|\n)answer\s*:\s*/i,
  ];

  for (const marker of markers) {
    const match = marker.exec(content);
    if (match) {
      return content.slice((match.index ?? 0) + match[0].length).trim();
    }
  }

  return content;
}

function looksLikeInternalReasoning(content: string): boolean {
  const start = content.slice(0, 700);
  const leakPatterns = [
    /^the user is asking\b/i,
    /^we need to\b/i,
    /^i need to\b/i,
    /^i should\b/i,
    /^looking at the conversation history\b/i,
    /^so they want\b/i,
    /^let me\b/i,
    /^actually,?\s+looking\b/i,
    /\bconversation history:\b/i,
    /\bi should:\b/i,
    /\bthe user provided\b/i,
    /\bprevious confusing\/cut-off responses\b/i,
  ];

  return leakPatterns.some((pattern) => pattern.test(start));
}

function buildReasoningLeakFallback(question: string, evidence: ConversationEvidence): string {
  if (/\b(you there|are you there|hello|hi|hey|huh)\b/i.test(question)) {
    return [
      "Yes, I am here.",
      "I can help you scan this project, explain the latest report, revise a fix prompt, or set a scan automation.",
    ].join("\n");
  }

  if (/\b(scan|start scan|run scan|rescan)\b/i.test(question)) {
    return "I can run the Online scan pipeline for the selected project. Say `scan project` and Hermsec will start the scan.";
  }

  if (/\b(automation|schedule|cron|recurring)\b/i.test(question)) {
    return "I can set an in-app scan automation. Tell me the cadence and exact time, for example: `run every 2 days at 09:00`.";
  }

  return buildConversationalFallback(question, evidence);
}

function resolveModelConfig(): { baseUrl: string; apiKey?: string; modelId: string; maxTokens: number; historyTurns: number } | null {
  const settings = readSettings();
  const candidates = settings.providers.filter((provider) => provider.enabled);
  const provider =
    candidates.find((item) => item.id === settings.activeProviderId && item.models.some((model) => model.enabled && model.id === settings.activeModelId)) ??
    candidates.find((item) => item.models.some((model) => model.enabled && model.id === settings.activeModelId)) ??
    candidates[0];
  if (!provider) return null;

  const model =
    provider.models.find((item) => item.enabled && item.id === settings.activeModelId) ??
    provider.models.find((item) => item.enabled);
  const apiKey = resolveProviderApiKey(provider);
  if (!model?.id || !provider.baseUrl?.trim() || (!apiKey && !providerAllowsNoApiKey(provider))) return null;

  return {
    baseUrl: provider.baseUrl.trim().replace(/\/$/, ""),
    apiKey,
    modelId: model.id,
    maxTokens: modelBudget(settings.general.thinkingLevel),
    historyTurns: contextTurns(settings.general.contextWindow),
  };
}

function modelBudget(level: string | undefined): number {
  if (level === "fast") return 550;
  if (level === "deep") return 1400;
  return 900;
}

function contextTurns(window: string | undefined): number {
  if (window === "compact") return 4;
  if (window === "large") return 14;
  return 8;
}

function resolveProviderApiKey(provider: ProviderConfig): string | undefined {
  if (providerAllowsNoApiKey(provider)) return undefined;
  if (provider.apiKey?.trim()) return provider.apiKey.trim();
  const envNames = [
    provider.apiKeyEnvVar,
    process.env.HERMSEC_MODEL_API_KEY_ENV,
    provider.id === "opencode-go" ? "OPENCODE_GO_API_KEY" : undefined,
    "HERMSEC_MODEL_API_KEY",
  ]
    .map(cleanEnvValue)
    .filter((name): name is string => Boolean(name));

  for (const envName of Array.from(new Set(envNames))) {
    const value = process.env[envName]?.trim();
    if (value) return value;
  }

  return undefined;
}

function providerAllowsNoApiKey(provider: ProviderConfig): boolean {
  return provider.id === "ollama-local" || provider.presetId === "ollama-local";
}

function cleanEnvValue(value: string | undefined): string | undefined {
  const trimmed = value?.trim().replace(/^["']|["']$/g, "");
  return trimmed ? trimmed : undefined;
}

function buildConversationalFallback(question: string, evidence: ConversationEvidence): string {
  const lower = question.toLowerCase();
  const top = evidence.findings[0];

  if (evidence.findings.length === 0) {
    if (evidence.note) {
      return [
        "I am available.",
        `I can answer questions about ${evidence.targetName}, configure scans or automations, explain Hermsec behavior, and review exact findings after a scan is available.`,
        "",
        "Available actions: scan this project, set an automation, explain the app, or review security risks.",
      ].join("\n");
    }
    return [
      `The latest scan for ${evidence.targetName} did not record findings in the report artifacts I can read.`,
      "That is good news, but it is not a proof of perfect safety. I would still rerun the scan after meaningful dependency or auth/input-handling changes.",
    ].join("\n");
  }

  if (/\b(where|line|file|show|code)\b/.test(lower)) {
    return [
      `Here are the clearest places to start in ${evidence.targetName}:`,
      ...evidence.findings.slice(0, 5).map((finding, index) =>
        [
          `${index + 1}. ${finding.severity}: ${finding.title}`,
          `   Where: ${finding.location}`,
          finding.code ? `   Code: ${finding.code}` : "",
          `   Why: ${finding.description}`,
        ].filter(Boolean).join("\n"),
      ),
      "",
      "Pick one of those and ask me to walk through it; I can break down why it is risky and what a safe patch should look like.",
    ].join("\n");
  }

  if (/\b(fix|patch|remed|first|priority|next)\b/.test(lower)) {
    return [
      `I would start with the highest-impact finding in ${evidence.targetName}: ${top.severity} - ${top.title}.`,
      `Location: ${top.location}`,
      top.code ? `Code: ${top.code}` : "",
      "",
      `Why it matters: ${top.description}`,
      `How I would approach the fix: ${top.remediation}`,
      "",
      "Then rerun the online scan and compare the dashboard. If you want, ask me for a copy-ready fix prompt for another coding agent.",
    ].filter(Boolean).join("\n");
  }

  if (/\b(have you|scanned|scan|report|found)\b/.test(lower)) {
    return [
      `Yes, I have the latest report for ${evidence.targetName}.`,
      `It found ${evidence.counts.total} findings: ${evidence.counts.critical} critical, ${evidence.counts.high} high, ${evidence.counts.medium} medium, ${evidence.counts.low} low, and ${evidence.counts.info} info.`,
      `The top issue is ${top.severity} - ${top.title} at ${top.location}.`,
      "",
      "You can ask me to show locations, explain a finding, or help decide what to fix first.",
    ].join("\n");
  }

  return [
    `I can walk through the current security posture for ${evidence.targetName}.`,
    `The report has ${evidence.counts.total} findings, and the first thing I would inspect is ${top.severity} - ${top.title} at ${top.location}.`,
    "",
    `In plain terms: ${top.description}`,
    `The likely fix direction is: ${top.remediation}`,
    "",
    "Tell me which finding you want to unpack, or ask \"show me where\" to see the file and line evidence.",
  ].join("\n");
}

function normalizeCounts(summary: Record<string, unknown> | undefined, findings: Finding[]) {
  const countSeverity = (severity: string) =>
    findings.filter((finding) => finding.severity?.toLowerCase() === severity).length;
  return {
    total: numberValue(summary?.total, findings.length),
    critical: numberValue(summary?.critical, countSeverity("critical")),
    high: numberValue(summary?.high, countSeverity("high")),
    medium: numberValue(summary?.medium, countSeverity("medium")),
    low: numberValue(summary?.low, countSeverity("low")),
    info: numberValue(summary?.info, countSeverity("info")),
    secrets: numberValue(summary?.secrets, findings.filter((finding) => finding.category === "secret").length),
    scannerFailures: numberValue(summary?.scannerFailures, 0),
  };
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => (rank[a.severity ?? "info"] ?? 5) - (rank[b.severity ?? "info"] ?? 5));
}

type FixPromptStyle = "standard" | "phased";

function classifyPromptStyle(question: string, previousPrompt?: string): FixPromptStyle {
  if (/\b(phase|phases|phased|break it down|stages?|step by step|milestones?)\b/i.test(question)) {
    return "phased";
  }
  if (previousPrompt && /\b(phase|phases|phased)\b/i.test(previousPrompt)) {
    return "phased";
  }
  return "standard";
}

function buildFixAgentPrompt({
  reportPath,
  targetName,
  projectRoot,
  counts,
  findings,
  style = "standard",
}: {
  reportPath: string;
  targetName: string;
  projectRoot?: string;
  counts: ReturnType<typeof normalizeCounts>;
  findings: Finding[];
  style?: FixPromptStyle;
}): string {
  if (style === "phased") {
    return buildPhasedFixAgentPrompt({ reportPath, targetName, projectRoot, counts, findings });
  }

  const ordered = sortFindings(findings).slice(0, 12);
  const findingLines = ordered.map((finding, index) => formatPromptFinding(finding, index + 1, projectRoot));

  return [
    "You are a defensive security coding agent. Fix the scanner-backed Hermsec security findings in this repository.",
    "",
    "Repository:",
    projectRoot ?? "Use the currently opened repository.",
    "",
    "Hermsec report:",
    reportPath,
    "",
    "Report summary:",
    `- Project: ${targetName}`,
    `- Findings: ${counts.total} total, ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info`,
    `- Secrets flagged: ${counts.secrets}`,
    "",
    "Rules of engagement:",
    "- Make narrow, source-level fixes for the listed findings only.",
    "- Preserve app behavior unless the current behavior is the vulnerability.",
    "- Do not delete findings, tests, or security evidence to make the scan look clean.",
    "- Never print or commit real secrets. If a secret is present, remove it from source, replace it with an environment/config reference, and mention that the exposed value must be rotated.",
    "- Prefer validation, escaping, parameterized APIs, safe argv arrays, and dependency upgrades over suppressions.",
    "- If a finding is a likely false positive, explain why with code evidence instead of silently ignoring it.",
    "",
    "Findings to address, in priority order:",
    ...findingLines,
    "",
    "Verification required:",
    "- Run the smallest relevant tests/build checks for the changed code.",
    "- Rerun Hermsec or the relevant security scanner after fixes when available.",
    "- Report exactly which files changed, which findings were fixed, which findings remain, and which verification commands passed or failed.",
  ].join("\n");
}

function buildPhasedFixAgentPrompt({
  reportPath,
  targetName,
  projectRoot,
  counts,
  findings,
}: {
  reportPath: string;
  targetName: string;
  projectRoot?: string;
  counts: ReturnType<typeof normalizeCounts>;
  findings: Finding[];
}): string {
  const ordered = sortFindings(findings).slice(0, 12);
  const secretFindings = ordered.filter(isSecretFinding);
  const executionFindings = ordered.filter(isExecutableCodeFinding);
  const dependencyFindings = ordered.filter(isDependencyFinding);
  const remainingFindings = ordered.filter(
    (finding) => !isSecretFinding(finding) && !isExecutableCodeFinding(finding) && !isDependencyFinding(finding),
  );

  return [
    "You are a defensive security coding agent. Fix the scanner-backed Hermsec security findings in this repository in clear phases.",
    "",
    "Repository:",
    projectRoot ?? "Use the currently opened repository.",
    "",
    "Hermsec report:",
    reportPath,
    "",
    "Report summary:",
    `- Project: ${targetName}`,
    `- Findings: ${counts.total} total, ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info`,
    `- Secrets flagged: ${counts.secrets}`,
    "",
    "Rules of engagement:",
    "- Make narrow source-level fixes for the listed findings only.",
    "- Preserve app behavior unless the current behavior is the vulnerability.",
    "- Do not delete findings, tests, lockfiles, scanner output, or security evidence to make the scan look clean.",
    "- Never print or commit real secrets. Remove exposed secrets from source, replace them with env/config references, and state that exposed values must be rotated.",
    "- If a finding is a likely false positive, explain why with code evidence instead of silently ignoring it.",
    "- After every phase, summarize files changed, findings addressed, findings deferred, and verification status.",
    "",
    "Phase 0 - Baseline and planning:",
    "- Read the Hermsec report and inspect each affected file before editing.",
    "- Confirm the project type, package manager, test/build commands, and whether lockfiles are expected.",
    "- Create a short implementation plan ordered by exploitability: secrets, command/code execution, injection/XSS, dependency and package hygiene, then lower-severity cleanup.",
    "",
    phaseBlock("Phase 1 - Secrets and credential safety", secretFindings, [
      "Remove credential-like values from source.",
      "Replace hardcoded values with environment variables or a local config placeholder.",
      "Do not reveal the secret value in logs, comments, commits, or summaries.",
      "Call out that any committed/exposed value must be rotated outside the codebase.",
    ], projectRoot),
    "",
    phaseBlock("Phase 2 - Critical executable-code and injection risks", executionFindings, [
      "Replace shell string execution with fixed argv arrays or safe library APIs.",
      "Validate and constrain user-controlled input before it reaches sensitive sinks.",
      "Remove unsafe eval/dynamic execution paths unless there is a safe, documented replacement.",
      "Add focused regression coverage if the app already has a suitable test harness.",
    ], projectRoot),
    "",
    phaseBlock("Phase 3 - Dependency and supply-chain hygiene", dependencyFindings, [
      "Review package and lockfile findings.",
      "Commit the appropriate lockfile after dependency review; do not generate one during an unsafe install step unless explicitly approved.",
      "Prefer pinned, maintained packages and document any dependency update or removal.",
      "Rerun the smallest relevant dependency/security check when possible.",
    ], projectRoot),
    "",
    phaseBlock("Phase 4 - Remaining security hardening", remainingFindings, [
      "Address remaining medium/info findings with narrow code changes.",
      "Escape untrusted output before rendering HTML responses.",
      "Use safe parsing, encoding, validation, and framework protections where applicable.",
      "Document any finding intentionally left for later with a reason and risk level.",
    ], projectRoot),
    "",
    "Phase 5 - Verification and final handoff:",
    "- Run the smallest relevant tests/build checks for the changed code.",
    "- Rerun Hermsec or the relevant scanner after fixes when available.",
    "- Report exactly which files changed.",
    "- Report which Hermsec findings were fixed, which remain, and which commands passed or failed.",
    "- Do not claim the project is secure unless scanner evidence and tests support that claim.",
    "",
    "Full findings appendix:",
    ...ordered.map((finding, index) => formatPromptFinding(finding, index + 1, projectRoot)),
  ].join("\n");
}

function phaseBlock(title: string, phaseFindings: Finding[], actions: string[], projectRoot?: string): string {
  return [
    `${title}:`,
    ...actions.map((action) => `- ${action}`),
    phaseFindings.length ? "- Findings in this phase:" : "- Findings in this phase: none detected by the latest report; still verify the phase is not applicable.",
    ...phaseFindings.map((finding, index) =>
      formatPromptFinding(finding, index + 1, projectRoot)
        .split("\n")
        .map((line) => `  ${line}`)
        .join("\n"),
    ),
  ].join("\n");
}

function isSecretFinding(finding: Finding): boolean {
  return finding.category === "secret" || /secret|token|credential|api[_ -]?key|password/i.test(`${finding.title ?? ""} ${finding.description ?? ""}`);
}

function isExecutableCodeFinding(finding: Finding): boolean {
  return /command|shell|exec|eval|dynamic code|injection|xss|csrf|xsrf|sql/i.test(
    `${finding.title ?? ""} ${finding.description ?? ""} ${finding.ruleId ?? ""}`,
  );
}

function isDependencyFinding(finding: Finding): boolean {
  return /dependency|package|lockfile|npm|pip|osv|audit|supply/i.test(
    `${finding.title ?? ""} ${finding.description ?? ""} ${finding.ruleId ?? ""}`,
  );
}

function writePromptArtifact(reportPath: string, prompt: string, style: FixPromptStyle): string | undefined {
  try {
    const promptDir = path.join(path.dirname(reportPath), "prompts");
    mkdirSync(promptDir, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const promptPath = path.join(promptDir, `hermsec-${style}-fix-prompt-${timestamp}.txt`);
    writeFileSync(promptPath, prompt, "utf8");
    return promptPath;
  } catch {
    return undefined;
  }
}

function formatPromptFinding(finding: Finding, index: number, projectRoot?: string): string {
  const location = formatLocation(finding) || "Location not recorded";
  const source = sourceLineSnippet(projectRoot, finding);
  return [
    `${index}. ${finding.severity?.toUpperCase() ?? "INFO"} - ${finding.title ?? "Security finding"}`,
    `   Location: ${location}`,
    `   Tool/rule: ${finding.tool ?? "unknown"}${finding.ruleId ? ` / ${finding.ruleId}` : ""}`,
    finding.cwe?.length ? `   CWE: ${finding.cwe.join(", ")}` : "",
    source ? `   Code: ${source}` : `   Evidence: ${redactSensitive(finding.evidence ?? "No source line was captured.")}`,
    `   Required fix: ${finding.remediation ?? "Review the evidence, patch the risky code path, and rerun the scan."}`,
  ].filter(Boolean).join("\n");
}

function formatBriefFinding(finding: Finding, index: number, projectRoot?: string): string {
  const location = formatLocation(finding);
  const source = sourceLineSnippet(projectRoot, finding);
  return `${index}. ${finding.severity?.toUpperCase() ?? "INFO"}: ${finding.title ?? "Security finding"}${location ? ` at ${location}` : ""}. ${finding.description ?? ""}${source ? `\n   Code: ${source}` : ""}`.trim();
}

function formatFixFinding(finding: Finding, index: number, projectRoot?: string): string {
  const location = formatLocation(finding);
  const source = sourceLineSnippet(projectRoot, finding);
  return [
    `${index}. ${finding.title ?? "Security finding"}${location ? ` (${location})` : ""}`,
    `   Why it matters: ${finding.description ?? "Hermsec found scanner evidence for this issue."}`,
    source ? `   Code: ${source}` : "",
    `   Fix: ${finding.remediation ?? "Review the evidence, patch the risky code path, and rerun the scan."}`,
  ].filter(Boolean).join("\n");
}

function formatLocatedFinding(finding: Finding, index: number, projectRoot?: string): string {
  const location = formatLocation(finding) || "Location not recorded";
  const source = sourceLineSnippet(projectRoot, finding);
  return [
    `${index}. ${finding.severity?.toUpperCase() ?? "INFO"}: ${finding.title ?? "Security finding"}`,
    `   Where: ${location}`,
    source ? `   Code: ${source}` : `   Evidence: ${redactSensitive(finding.evidence ?? "No source line was captured.")}`,
    `   Next: ${finding.remediation ?? "Review the evidence and patch the risky code path."}`,
  ].join("\n");
}

function formatLocation(finding: Finding): string {
  if (!finding.location?.file) return "";
  return `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`;
}

function sourceLineSnippet(projectRoot: string | undefined, finding: Finding): string {
  if (!projectRoot || !finding.location?.file || !finding.location.startLine) return "";
  try {
    const root = path.resolve(projectRoot);
    const filePath = path.resolve(root, finding.location.file);
    if (!normalizePath(filePath).startsWith(normalizePath(root))) return "";
    if (!existsSync(filePath)) return "";
    const lines = readFileSync(filePath, "utf8").split(/\r?\n/u);
    const line = lines[finding.location.startLine - 1]?.trim();
    if (!line) return "";
    return redactSensitive(line.length > 220 ? `${line.slice(0, 217)}...` : line);
  } catch {
    return "";
  }
}

function redactSensitive(value: string): string {
  return value
    .replace(/\b[A-Z0-9._%+-]*?(?:TOKEN|SECRET|API[_-]?KEY|PASSWORD)[A-Z0-9._%+-]*\b/giu, "[REDACTED_SECRET_NAME]")
    .replace(/(["']?)(?:token|secret|api[_-]?key|password)(\1?\s*[:=]\s*)(["']?)[^"'\s;,)]+/giu, "$1[REDACTED_SECRET_KEY]$2$3[REDACTED]")
    .replace(/[A-Za-z0-9_-]{24,}/g, "[REDACTED_SECRET]");
}

function formatReportDate(iso: string | undefined): string {
  if (!iso) return "at an unknown time";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "at an unknown time";
  return date.toLocaleString();
}

function normalizePath(filePath: string): string {
  return path.resolve(filePath).toLowerCase();
}
