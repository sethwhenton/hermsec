import { PencilIcon, PlayIcon, Trash2 } from "~/lib/icons";
import { Switch } from "~/components/ui/switch";
import { Button } from "~/components/ui/button";
import { cn } from "~/lib/utils";
import type { HermsecAutomation, HermsecReportPreview } from "../types";
import { HermsecPageShell } from "./HermsecPageShell";

type HermsecAutomationsPageProps = {
  automations: HermsecAutomation[];
  onToggleEnabled: (id: string, enabled: boolean) => void;
  onRunAutomation?: (id: string) => void;
  onDeleteAutomation?: (id: string) => void;
  onCreateAutomation?: () => void;
  onEditAutomation?: (id: string) => void;
  onOpenReport?: (report: HermsecReportPreview) => void;
};

function statusDotClass(status: HermsecAutomation["lastResult"]): string {
  switch (status) {
    case "success":
      return "bg-emerald-500/85";
    case "failed":
      return "bg-red-500/85";
    case "running":
      return "bg-amber-400/90 animate-pulse";
    default:
      return "bg-muted-foreground/35";
  }
}

function statusLabel(status: HermsecAutomation["lastResult"]): string {
  switch (status) {
    case "success":
      return "Passed";
    case "failed":
      return "Failed";
    case "running":
      return "Running";
    default:
      return "Idle";
  }
}

export function HermsecAutomationsPage({
  automations,
  onToggleEnabled,
  onRunAutomation,
  onDeleteAutomation,
  onCreateAutomation,
  onEditAutomation,
  onOpenReport,
}: HermsecAutomationsPageProps) {
  return (
    <HermsecPageShell className="flex flex-col gap-4">
      <div className="flex items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-lg font-semibold text-foreground/90">Automations</h1>
          <p className="text-[length:var(--app-font-size-ui,12px)] text-muted-foreground/70">
            Scheduled and on-demand security checks across local projects.
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="h-7 rounded-md text-[11px]"
          onClick={onCreateAutomation}
        >
          New automation
        </Button>
      </div>

      <div className="overflow-hidden rounded-lg border border-[color:var(--color-border)]">
        <div className="grid grid-cols-[minmax(0,1.4fr)_repeat(5,minmax(0,0.9fr))_auto] gap-2 border-b border-[color:var(--color-border)] bg-white/[0.02] px-3 py-2 text-[10px] font-medium tracking-wide text-muted-foreground/60 uppercase">
          <span>Automation</span>
          <span>Schedule</span>
          <span>Project</span>
          <span>Next run</span>
          <span>Last result</span>
          <span>Report folder</span>
          <span className="text-right">Actions</span>
        </div>

        {automations.map((automation, index) => (
          <div
            key={automation.id}
            className={cn(
              "grid grid-cols-[minmax(0,1.4fr)_repeat(5,minmax(0,0.9fr))_auto] items-center gap-2 px-3 py-2.5",
              index > 0 && "border-t border-[color:var(--color-border)]",
            )}
          >
            <div className="flex min-w-0 items-center gap-2">
              <Switch
                checked={automation.enabled}
                onCheckedChange={(checked) => onToggleEnabled(automation.id, checked)}
                aria-label={`Toggle ${automation.name}`}
              />
              <span className="truncate text-[length:var(--app-font-size-ui,12px)] text-foreground/88">
                {automation.name}
              </span>
            </div>
            <span className="truncate text-[11px] text-muted-foreground/75">{automation.schedule}</span>
            <span className="truncate text-[11px] text-muted-foreground/75">
              {automation.targetProject}
            </span>
            <span className="truncate text-[11px] text-muted-foreground/75">{automation.nextRun}</span>
            <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground/75">
              <span
                className={cn("size-1.5 shrink-0 rounded-full", statusDotClass(automation.lastResult))}
                aria-hidden
              />
              {statusLabel(automation.lastResult)}
            </span>
            <button
              type="button"
              className="truncate text-left text-[11px] text-muted-foreground/70 underline-offset-2 hover:text-foreground/80 hover:underline"
              onClick={() =>
                onOpenReport?.({
                  id: automation.id,
                  title: automation.name,
                  path: automation.reportFolder,
                  html: "",
                })
              }
            >
              {automation.reportFolder}
            </button>
            <div className="flex items-center justify-end gap-0.5">
              <Button
                size="icon-sm"
                variant="ghost"
                className="size-7 rounded-md text-muted-foreground/70"
                aria-label={`Run ${automation.name} now`}
                onClick={() => onRunAutomation?.(automation.id)}
              >
                <PlayIcon className="size-3.5" />
              </Button>
              <Button
                size="icon-sm"
                variant="ghost"
                className="size-7 rounded-md text-muted-foreground/70"
                aria-label={`Edit ${automation.name}`}
                onClick={() => onEditAutomation?.(automation.id)}
              >
                <PencilIcon className="size-3.5" />
              </Button>
              <Button
                size="icon-sm"
                variant="ghost"
                className="size-7 rounded-md text-muted-foreground/70 hover:text-destructive"
                aria-label={`Delete ${automation.name}`}
                onClick={() => onDeleteAutomation?.(automation.id)}
              >
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          </div>
        ))}
      </div>
    </HermsecPageShell>
  );
}
