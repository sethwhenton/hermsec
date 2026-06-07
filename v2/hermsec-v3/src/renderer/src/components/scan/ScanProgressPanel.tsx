import { CheckCircle2, Circle, Loader2, MinusCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import type { ScanProgressEvent, ScanProgressStatus } from "@/types/scan";

interface ScanProgressPanelProps {
  events: ScanProgressEvent[];
  compact?: boolean;
}

export function ScanProgressPanel({ events, compact }: ScanProgressPanelProps) {
  if (events.length === 0) return null;

  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-surface-elevated/95 shadow-[0_18px_60px_rgba(0,0,0,0.35)]",
        compact ? "p-3" : "p-4",
      )}
    >
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs font-medium text-foreground">Scan progress</div>
        <div className="text-[10px] uppercase tracking-wide text-muted">online</div>
      </div>
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
  if (status === "skipped") return <MinusCircle className="h-3.5 w-3.5 text-muted" />;
  return <Circle className="h-3.5 w-3.5 text-muted-foreground" />;
}

function statusColor(status: ScanProgressStatus): string {
  if (status === "running") return "text-accent";
  if (status === "completed") return "text-success";
  if (status === "failed") return "text-danger";
  return "text-muted";
}
