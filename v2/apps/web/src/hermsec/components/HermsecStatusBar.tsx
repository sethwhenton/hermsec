import { cn } from "~/lib/utils";

type HermsecStatusBarProps = {
  projectName?: string;
  projectPath?: string;
  scanMode: string;
  agentStatus: string;
};

export function HermsecStatusBar({
  projectName,
  projectPath,
  scanMode,
  agentStatus,
}: HermsecStatusBarProps) {
  return (
    <footer
      className={cn(
        "grid h-6 shrink-0 grid-cols-[minmax(8rem,1fr)_minmax(0,1.6fr)_minmax(8rem,1fr)] items-center gap-2",
        "border-t border-[color:var(--app-surface-divider)] bg-background px-2.5 text-[10px] text-muted-foreground/70",
      )}
      data-slot="hermsec-status-bar"
    >
      <div className="flex min-w-0 items-center gap-2">
        <span className="inline-flex items-center gap-1.5">
          <span className="size-1.5 rounded-full bg-emerald-500/80" aria-hidden />
          {agentStatus}
        </span>
      </div>

      <div
        className="flex min-w-0 items-center justify-center gap-1.5 text-muted-foreground/55"
        title={projectPath}
      >
        {projectName ? (
          <>
            <span className="shrink-0 text-muted-foreground/75">{projectName}</span>
            {projectPath ? <span className="text-muted-foreground/35">-</span> : null}
          </>
        ) : null}
        {projectPath ? (
          <span className="min-w-0 truncate">{projectPath}</span>
        ) : (
          <span className="text-muted-foreground/45">No project selected</span>
        )}
      </div>

      <div className="flex min-w-0 items-center justify-end gap-2">
        <span className="truncate">Scan: {scanMode}</span>
      </div>
    </footer>
  );
}
