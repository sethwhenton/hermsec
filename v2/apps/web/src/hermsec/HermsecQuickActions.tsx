// FILE: HermsecQuickActions.tsx
// Purpose: Lightweight Hermsec tool entrypoints inside the forked chat shell.
// Layer: Web UI / desktop bridge adapter

import { useState } from "react";

type ActionState = {
  label: string;
  status: "idle" | "running" | "done" | "error";
  output: string;
};

export function HermsecQuickActions() {
  const [state, setState] = useState<ActionState>({
    label: "Hermsec tools",
    status: "idle",
    output: "Select a folder, scan it, or refresh security intelligence.",
  });

  const available = Boolean(window.desktopBridge?.hermsec);

  async function runAction(label: string, action: () => Promise<{ ok: boolean; stdout: string; stderr: string }>) {
    setState({ label, status: "running", output: "Running..." });
    try {
      const result = await action();
      setState({
        label,
        status: result.ok ? "done" : "error",
        output: summarizeOutput(result.stdout || result.stderr || "No output returned."),
      });
    } catch (error) {
      setState({
        label,
        status: "error",
        output: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async function scanFolder() {
    const folder = await window.desktopBridge?.pickFolder();
    if (!folder) {
      setState({ label: "Scan", status: "idle", output: "No folder selected." });
      return;
    }
    await runAction("Scan", () => window.desktopBridge!.hermsec!.scan({ target: folder, mode: "offline" }));
  }

  if (!available) {
    return null;
  }

  return (
    <div className="mt-5 flex min-w-[min(34rem,calc(100vw-3rem))] max-w-xl flex-col gap-3 rounded-lg border border-border/60 bg-background/60 p-3 text-left shadow-sm backdrop-blur">
      <div className="grid grid-cols-3 gap-2">
        <button
          type="button"
          className="rounded-md border border-border/70 px-3 py-2 text-sm text-foreground/90 hover:bg-muted"
          onClick={() => void runAction("Doctor", () => window.desktopBridge!.hermsec!.doctor())}
        >
          Doctor
        </button>
        <button
          type="button"
          className="rounded-md border border-border/70 px-3 py-2 text-sm text-foreground/90 hover:bg-muted"
          onClick={() => void scanFolder()}
        >
          Scan Folder
        </button>
        <button
          type="button"
          className="rounded-md border border-border/70 px-3 py-2 text-sm text-foreground/90 hover:bg-muted"
          onClick={() => void runAction("Intel", () => window.desktopBridge!.hermsec!.updateIntel({ offline: false }))}
        >
          Intel
        </button>
      </div>
      <div className="rounded-md bg-muted/40 px-3 py-2">
        <div className="mb-1 text-xs font-medium uppercase text-muted-foreground">{state.label}</div>
        <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-muted-foreground">
          {state.output}
        </pre>
      </div>
    </div>
  );
}

function summarizeOutput(output: string): string {
  const compact = output
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .slice(0, 12)
    .join("\n");
  return compact.length > 1_200 ? `${compact.slice(0, 1_200)}...` : compact;
}
