export type AgentIntent =
  | "scan_target"
  | "explain_findings"
  | "show_report"
  | "configure_provider"
  | "configure_workspace"
  | "configure_schedule"
  | "update_security_intel"
  | "show_help"
  | "unsafe_or_out_of_scope"
  | "needs_clarification";

export type RoutedIntent = {
  intent: AgentIntent;
  reason: string;
  findingId?: string;
};

const unsafePattern =
  /\b(?:edit|rewrite|patch|delete|overwrite|commit|push|run shell|shell|terminal|cmd\.exe|powershell|bash|install|npm install|pnpm install|yarn install|bun install|pip install|exploit|payload|reverse shell|bypass|exfiltrate|dump secret|read secret|show token|api key)\b/i;

export function routeAgentIntent(input: string): RoutedIntent {
  const text = input.trim();
  const lower = text.toLowerCase();
  const findingId = text.match(/\bHERM-[A-Za-z0-9_-]+\b/i)?.[0];

  if (!text) {
    return { intent: "needs_clarification", reason: "No request was provided." };
  }
  if (unsafePattern.test(text)) {
    return {
      intent: "unsafe_or_out_of_scope",
      reason: "Request asks for capabilities outside Hermsec's restricted defensive runtime."
    };
  }
  if (lower === "/help" || /\bhelp\b/.test(lower)) {
    return { intent: "show_help", reason: "User asked for supported Hermsec commands." };
  }
  if (lower.startsWith("/scan") || /\b(scan|check|review)\b/.test(lower)) {
    return { intent: "scan_target", reason: "User asked Hermsec to run scanners." };
  }
  if (lower.startsWith("/explain") || /\b(why|explain|impact|fix|remediate)\b/.test(lower)) {
    return { intent: "explain_findings", reason: "User asked for explanation of scanner evidence.", ...(findingId ? { findingId } : {}) };
  }
  if (lower.startsWith("/reports") || /\b(report|open latest|show latest)\b/.test(lower)) {
    return { intent: "show_report", reason: "User asked for a report." };
  }
  if (/\b(provider|model|openai|opencode|ollama|api key)\b/.test(lower)) {
    return { intent: "configure_provider", reason: "User asked about model provider configuration." };
  }
  if (/\b(workspace|folder|repo|repository)\b/.test(lower)) {
    return { intent: "configure_workspace", reason: "User asked about workspace configuration." };
  }
  if (/\b(schedule|daily|watch|idle)\b/.test(lower)) {
    return { intent: "configure_schedule", reason: "User asked about scheduled scans." };
  }
  if (/\b(intel|advisory|security news|cisa|kev|osv)\b/.test(lower)) {
    return { intent: "update_security_intel", reason: "User asked about security intelligence." };
  }
  return { intent: "needs_clarification", reason: "Request does not map to a safe Hermsec action." };
}
