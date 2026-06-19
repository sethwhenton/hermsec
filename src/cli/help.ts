export function rootHelp(): string {
  return [
    "Hermsec CLI",
    "",
    "Usage:",
    "  hermsec",
    "  hermsec chat",
    "  hermsec agent ask <message> [--target <path>] [--mode auto|offline|online] [--json] [--no-model]",
    "  hermsec agent providers [--json]",
    "  hermsec doctor [--json]",
    "  hermsec onboard",
    "  hermsec scan <target> [--mode auto|offline|online] [--assist-mode scanner-model-summary|deep-assisted] [--out <dir>] [--json] [--md] [--html] [--no-model]",
    "  hermsec config get [key]",
    "  hermsec config set <key> <value>",
    "  hermsec config path",
    "  hermsec workspace list",
    "  hermsec workspace add [path] [--name <name>]",
    "  hermsec workspace use <id|name|path>",
    "  hermsec report list [--workspace <id>]",
    "  hermsec report open [latest|report-id|path]",
    "  hermsec report path [report-id] [--workspace <id>]",
    "  hermsec sync",
    "  hermsec schedule add <target> --daily <HH:mm> [--mode auto|offline|online]",
    "  hermsec schedule list",
    "  hermsec schedule run <schedule-id>",
    "  hermsec schedule remove <schedule-id>",
    "  hermsec watch <target> [--after-idle <duration>] [--mode auto|offline|online]",
    "  hermsec intel update [--workspace <id>] [--source cisa-kev|osv|github-advisory|nvd] [--offline]",
    "  hermsec eval run [--suite <path>] [--mode scanner-only|agent-assisted] [--out <dir>]",
    "  hermsec eval compare --scanner-only <summary.json> --agent-assisted <summary.json> [--out <file>]",
    "  hermsec eval explain-match [--suite <path>] --case <id> --finding <id>",
    "",
    "Hermsec is defensive by default: it does not install dependencies, run package executors, or execute lifecycle scripts from target repositories.",
  ].join("\n");
}

export function commandHelp(command: string): string {
  switch (command) {
    case "chat":
      return "Usage: hermsec chat";
    case "agent":
      return [
        "Usage:",
        "  hermsec agent ask <message> [--target <path>] [--mode auto|offline|online] [--json] [--no-model]",
        "  hermsec agent providers [--json]",
        "",
        "Agent chat is provider-agnostic and uses the provider/model configured in Hermsec settings.",
      ].join("\n");
    case "onboard":
      return "Usage: hermsec onboard";
    case "doctor":
      return "Usage: hermsec doctor [--json]";
    case "scan":
      return "Usage: hermsec scan <target> [--mode auto|offline|online] [--assist-mode scanner-model-summary|deep-assisted] [--out <dir>] [--json] [--md] [--html] [--no-model]";
    case "config":
      return [
        "Usage: hermsec config get [key] | set <key> <value> | path",
        "",
        "Common keys:",
        "  privacyMode local-only|balanced|cloud-assisted",
        "  preferredModelProvider none|ollama|openrouter|openai|claude|gemini|opencode-go|openai-compatible",
        "  providerCredentialEnv <ENV_VAR_NAME>",
        "  defaultReportLocation app-data|project-local|custom|ask",
        "  customReportDir <path>",
      ].join("\n");
    case "workspace":
      return "Usage: hermsec workspace list | add [path] [--name <name>] | use <id|name|path>";
    case "report":
      return "Usage: hermsec report list [--workspace <id>] | open [latest|report-id|path] | path [report-id] [--workspace <id>]";
    case "schedule":
      return "Usage: hermsec schedule add <target> --daily <HH:mm> [--mode auto|offline|online] | list | run <schedule-id> | remove <schedule-id>";
    case "watch":
      return "Usage: hermsec watch <target> [--after-idle <duration>] [--mode auto|offline|online]";
    case "intel":
      return "Usage: hermsec intel update [--workspace <id>] [--source cisa-kev|osv|github-advisory|nvd] [--offline]";
    case "eval":
      return "Usage: hermsec eval run|compare|explain-match [options]";
    default:
      return rootHelp();
  }
}

export function helpResult(message = rootHelp()) {
  return {
    ok: true as const,
    message,
  };
}

export function usageError(message: string, usage: string) {
  return {
    ok: false as const,
    errorCode: "USAGE_ERROR",
    message,
    remediation: `Run ${usage} for help.`,
  };
}
