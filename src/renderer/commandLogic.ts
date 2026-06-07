export type ComposerCommand =
  | "scan"
  | "intel"
  | "doctor"
  | "reports"
  | "settings"
  | "help"
  | "unknown";

export type ParsedComposerCommand = {
  command: ComposerCommand;
  args: string;
};

export const slashCommands = [
  { command: "/scan", description: "Run scan harness and save report" },
  { command: "/intel", description: "Refresh vulnerability intelligence" },
  { command: "/doctor", description: "Check local tool readiness" },
  { command: "/reports", description: "List saved reports" },
  { command: "/settings", description: "Open privacy and model settings" },
  { command: "/help", description: "Show Hermsec commands" },
] as const;

export function parseComposerCommand(input: string): ParsedComposerCommand | undefined {
  const trimmed = input.trim();
  if (!trimmed.startsWith("/")) {
    return undefined;
  }
  const [rawCommand = "", ...rest] = trimmed.split(/\s+/);
  const args = rest.join(" ");
  switch (rawCommand.toLowerCase()) {
    case "/scan":
      return { command: "scan", args };
    case "/intel":
      return { command: "intel", args };
    case "/doctor":
      return { command: "doctor", args };
    case "/reports":
      return { command: "reports", args };
    case "/settings":
      return { command: "settings", args };
    case "/help":
    case "/commands":
      return { command: "help", args };
    default:
      return { command: "unknown", args };
  }
}
