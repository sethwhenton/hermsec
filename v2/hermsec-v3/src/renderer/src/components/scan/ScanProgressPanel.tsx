import { useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight, Circle, Loader2, MinusCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import type { ScanProgressEvent, ScanProgressStatus } from "@/types/scan";

interface ScanProgressPanelProps {
  events: ScanProgressEvent[];
  compact?: boolean;
  embedded?: boolean;
}

export function ScanProgressDisclosure({
  events,
  running,
  visible,
}: {
  events: ScanProgressEvent[];
  running?: boolean;
  visible?: boolean;
}) {
  const [open, setOpen] = useState(false);

  if (!visible || events.length === 0) return null;

  const completed = events.filter((event) => event.status === "completed").length;
  const failed = events.filter((event) => event.status === "failed").length;
  const canceled = events.some((event) => event.status === "canceled");
  const active = [...events].reverse().find((event) => event.status === "running");
  const summary = canceled
    ? "Stopped"
    : failed
      ? `${failed} failed`
      : running
        ? active
        ? `${active.label} running`
        : "Running"
      : `${completed}/${events.length} complete`;

  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-surface-elevated/75 shadow-[0_16px_45px_rgba(0,0,0,0.24)]">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors duration-150 ease-out active:scale-[0.995] hover:bg-surface-hover/60"
        onClick={() => setOpen((current) => !current)}
      >
        <div className="flex min-w-0 items-center gap-3">
          {running ? (
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-accent" />
          ) : canceled ? (
            <MinusCircle className="h-4 w-4 shrink-0 text-muted" />
          ) : failed ? (
            <XCircle className="h-4 w-4 shrink-0 text-danger" />
          ) : (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
          )}
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground">Scan progress</div>
            <div className="truncate text-xs text-muted-foreground">{summary}</div>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="text-[10px] uppercase tracking-wide text-muted">online</span>
          {open ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </button>
      {open ? (
        <div className="border-t border-border/70 px-3 pb-3 pt-2">
          <ScanProgressPanel events={events} compact embedded />
        </div>
      ) : null}
    </div>
  );
}

export function ScanProgressPanel({ events, compact, embedded }: ScanProgressPanelProps) {
  if (events.length === 0) return null;

  return (
    <div
      className={cn(
        embedded
          ? "rounded-none border-0 bg-transparent shadow-none"
          : "rounded-xl border border-border bg-surface-elevated/95 shadow-[0_18px_60px_rgba(0,0,0,0.35)]",
        compact ? (embedded ? "p-0" : "p-3") : "p-4",
      )}
    >
      {!embedded ? (
        <div className="mb-2 flex items-center justify-between">
          <div className="text-xs font-medium text-foreground">Scan progress</div>
          <div className="text-[10px] uppercase tracking-wide text-muted">online</div>
        </div>
      ) : null}
      <div className={cn("grid gap-1.5", compact ? "max-h-48 overflow-y-auto" : "max-h-72 overflow-y-auto")}>
        {events.map((event) => (
          <div
            key={event.id}
            className="grid grid-cols-[18px_1fr_auto] items-center gap-2 rounded-md px-1.5 py-1 text-xs"
          >
            <ProgressIcon status={event.status} />
            <div className="min-w-0">
              <div className="truncate text-foreground">{event.label}</div>
              {event.message ? (
                <div className="truncate text-[11px] text-muted-foreground">{event.message}</div>
              ) : null}
            </div>
            <span className={cn("text-[10px] uppercase", statusColor(event.status))}>
              {event.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ProgressIcon({ status }: { status: ScanProgressStatus }) {
  if (status === "running") return <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />;
  if (status === "completed") return <CheckCircle2 className="h-3.5 w-3.5 text-success" />;
  if (status === "failed") return <XCircle className="h-3.5 w-3.5 text-danger" />;
  if (status === "canceled") return <MinusCircle className="h-3.5 w-3.5 text-muted" />;
  if (status === "skipped") return <MinusCircle className="h-3.5 w-3.5 text-muted" />;
  return <Circle className="h-3.5 w-3.5 text-muted-foreground" />;
}

function statusColor(status: ScanProgressStatus): string {
  if (status === "running") return "text-accent";
  if (status === "completed") return "text-success";
  if (status === "failed") return "text-danger";
  if (status === "canceled") return "text-muted";
  return "text-muted";
}
