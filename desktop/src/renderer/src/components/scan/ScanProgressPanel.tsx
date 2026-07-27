import { useMemo, useState } from "react";
import { Check, ChevronDown, ChevronRight, Circle, Minus, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { normalizeScanAssistMode, scanModeLabel } from "@/lib/scanModes";
import type { ScanProgressDetail, ScanProgressEvent, ScanProgressStatus } from "@/types/scan";
import Spiral5x5 from "@/components/ui/Spiral5x5";

interface ScanProgressPanelProps {
  events: ScanProgressEvent[];
  compact?: boolean;
  embedded?: boolean;
}

const timelineStages = [
  { id: "inspect-project", label: "Inspecting project" },
  { id: "choose-tools", label: "Choosing scanner tools" },
  { id: "prepare-tools", label: "Preparing tools" },
  { id: "running-scans", label: "Running scans" },
  { id: "model-summary", label: "Model summary" },
  { id: "report-ready", label: "Report ready" },
] as const;

const timelineStageIds = new Set<string>(timelineStages.map((stage) => stage.id));

export function ScanProgressDisclosure({
  events,
  running,
  visible,
}: {
  events: ScanProgressEvent[];
  running?: boolean;
  visible?: boolean;
}) {
  const model = useMemo(() => buildTimelineModel(events), [events]);
  const activeStage = model.stages.find((stage) => stage.status === "running");
  const firstExpandable = activeStage?.id ?? model.stages.find((stage) => stage.details.length > 0)?.id;
  const [manuallyOpen, setManuallyOpen] = useState<string | null>(null);
  const openStageId = manuallyOpen ?? firstExpandable ?? null;

  if (!visible || events.length === 0) return null;

  const latestFinishedStage = [...model.stages].reverse().find((stage) => stage.status !== "waiting");
  const statusLine = activeStage?.message
    ?? latestFinishedStage?.message
    ?? "Scanning to see which tools this project needs...";

  return (
    <div className="flex w-full justify-start">
      <div className="w-full max-w-[min(680px,96%)] overflow-hidden rounded-[22px] border border-border/80 bg-surface-elevated/80 text-foreground shadow-[0_16px_50px_rgba(0,0,0,0.24)] backdrop-blur">
        <div className="scan-buffer-line" aria-hidden />
        <div className="px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm text-foreground">{statusLine}</p>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {model.chips.slice(0, 7).map((chip) => (
                  <span
                    key={chip}
                    className="rounded-md border border-border/75 bg-background/45 px-2 py-0.5 text-[11px] text-muted"
                  >
                    {chip}
                  </span>
                ))}
              </div>
            </div>
            <span className="shrink-0 rounded-md border border-border/75 bg-background/45 px-2 py-1 text-[11px] text-muted">
              {running ? "Running" : model.done ? "Done" : "Queued"}
            </span>
          </div>

          <div className="mt-5">
            {model.stages.map((stage, index) => {
              const open = openStageId === stage.id && stage.details.length > 0;
              return (
                <div key={stage.id} className="relative grid grid-cols-[28px_1fr] gap-3">
                  {index < model.stages.length - 1 ? (
                    <div
                      className={cn(
                        "absolute left-[13px] top-7 h-[calc(100%-10px)] w-px",
                        stage.status === "completed" ? "bg-zinc-500/60" : "bg-border",
                      )}
                    />
                  ) : null}
                  <StageIcon status={stage.status} active={stage.status === "running"} />
                  <div className="min-w-0 pb-4">
                    <button
                      type="button"
                      className="group flex w-full min-w-0 items-center justify-between gap-3 rounded-md px-1 py-0.5 text-left transition-colors duration-150 ease-out hover:bg-white/[0.03] active:scale-[0.995]"
                      onClick={() => {
                        if (stage.details.length === 0) return;
                        setManuallyOpen((current) => (current === stage.id ? "" : stage.id));
                      }}
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className={cn(
                            "truncate text-sm",
                            stage.status === "running" ? "font-semibold text-foreground" : "text-muted",
                            stage.status === "completed" ? "text-foreground" : "",
                          )}
                        >
                          {index + 1}. {stage.label}
                        </span>
                        {stage.details.length > 0 ? (
                          open ? (
                            <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                          )
                        ) : null}
                      </div>
                      <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                        {stage.value ?? stageDuration(stage)}
                      </span>
                    </button>
                    {open ? <StageDetails details={stage.details} /> : null}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center gap-2 border-t border-border/70 pt-3">
            <span className="rounded-md border border-border/75 bg-background/45 px-2 py-1 text-[11px] text-muted">
              {model.mode}
            </span>
            <span className="rounded-md border border-border/75 bg-background/45 px-2 py-1 text-[11px] text-muted">
              {model.tokenLabel}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ScanProgressPanel({ events, compact, embedded }: ScanProgressPanelProps) {
  if (events.length === 0) return null;
  const visibleEvents = events.filter((event) => event.id !== "scan-assist-mode");

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
        {visibleEvents.map((event) => (
          <div
            key={event.id}
            className="grid grid-cols-[18px_1fr_auto] items-center gap-2 rounded-md px-1.5 py-1 text-xs"
          >
            <SmallStatusIcon status={event.status} />
            <div className="min-w-0">
              <div className="truncate text-foreground">{event.label}</div>
              {event.message ? (
                <div className="truncate text-[11px] text-muted-foreground">{event.message}</div>
              ) : null}
            </div>
            <span className="text-[10px] uppercase text-muted">{event.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StageDetails({ details }: { details: ScanProgressDetail[] }) {
  return (
    <div className="mt-2 space-y-1 border-l border-border/80 pl-3">
      {details.map((detail, index) => (
        <div key={detail.id ?? `${detail.label}-${index}`} className="grid grid-cols-[18px_1fr_auto] items-start gap-2 py-1 text-xs">
          <SmallStatusIcon status={detail.status} />
          <div className="min-w-0">
            <div className="truncate text-foreground/90">{detail.label}</div>
            {detail.message ? <div className="mt-0.5 line-clamp-2 text-muted-foreground">{detail.message}</div> : null}
          </div>
          {detail.value ? (
            <span className="max-w-[120px] truncate rounded-md border border-border/70 bg-background/40 px-1.5 py-0.5 text-[10px] text-muted">
              {detail.value}
            </span>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function StageIcon({ status, active }: { status: ScanProgressStatus; active?: boolean }) {
  if (status === "completed") {
    return (
      <span className="relative z-10 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border border-zinc-500/70 bg-zinc-800 text-zinc-100">
        <Check className="h-3.5 w-3.5" />
      </span>
    );
  }
  if (status === "running") {
    return (
      <span className="relative z-10 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border border-zinc-400/80 bg-zinc-900 text-zinc-100">
        <Spiral5x5 size={13} gap={1} className={cn(active ? "opacity-100" : "opacity-70")} />
      </span>
    );
  }
  if (status === "failed" || status === "degraded") {
    return (
      <span className="relative z-10 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border border-zinc-600 bg-zinc-900 text-zinc-300">
        <X className="h-3.5 w-3.5" />
      </span>
    );
  }
  if (status === "skipped" || status === "canceled") {
    return (
      <span className="relative z-10 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border border-zinc-700 bg-zinc-950 text-zinc-500">
        <Minus className="h-3.5 w-3.5" />
      </span>
    );
  }
  return (
    <span className="relative z-10 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full border border-zinc-700 bg-zinc-950 text-zinc-500">
      <Circle className="h-3.5 w-3.5" />
    </span>
  );
}

function SmallStatusIcon({ status }: { status: ScanProgressStatus }) {
  if (status === "running") return <Spiral5x5 size={11} gap={1} className="mt-0.5 text-zinc-200" />;
  if (status === "completed") return <Check className="mt-0.5 h-3.5 w-3.5 text-zinc-200" />;
  if (status === "failed" || status === "degraded") return <X className="mt-0.5 h-3.5 w-3.5 text-zinc-300" />;
  if (status === "skipped" || status === "canceled") return <Minus className="mt-0.5 h-3.5 w-3.5 text-zinc-500" />;
  return <Circle className="mt-0.5 h-3.5 w-3.5 text-zinc-500" />;
}

function buildTimelineModel(events: ScanProgressEvent[]) {
  const byId = new Map(events.map((event) => [event.id, event]));
  const childrenByParent = new Map<string, ScanProgressEvent[]>();
  const chips = new Set<string>();

  for (const event of events) {
    event.chips?.forEach((chip) => chips.add(chip));
    const parentId = event.parentId ?? inferParentStageId(event);
    if (parentId) {
      const current = childrenByParent.get(parentId) ?? [];
      current.push(event);
      childrenByParent.set(parentId, current);
    }
  }

  const stages = timelineStages.map((stage) => {
    const event = byId.get(stage.id);
    const childDetails = (childrenByParent.get(stage.id) ?? []).flatMap(eventToDetails);
    const details = [...(event?.details ?? []), ...childDetails];
    return {
      id: stage.id,
      label: event?.label ?? stage.label,
      status: event?.status ?? "waiting",
      message: event?.message,
      timestamp: event?.timestamp,
      details: dedupeDetails(details),
      value: valueForStage(event),
    };
  });

  const modeEvent = [...events]
    .reverse()
    .find((event) => event.assistMode || event.assistModeLabel || event.id === "scan-assist-mode");
  const inferredMode = normalizeScanAssistMode(modeEvent?.assistMode);
  const mode = modeEvent?.assistModeLabel
    ? modeEvent.assistModeLabel
    : scanModeLabel(inferredMode);

  return {
    stages,
    chips: Array.from(chips),
    mode,
    tokenLabel: tokenLabelForMode(inferredMode),
    done: stages.every((stage) => ["completed", "skipped", "degraded", "failed", "canceled"].includes(stage.status)),
  };
}

function tokenLabelForMode(mode: string): string {
  if (mode === "scanner-only") return "No model calls";
  if (mode === "single-agent") return "Focused agent review";
  if (mode === "moa-low") return "Three specialists";
  if (mode === "moa-high") return "Five specialists";
  if (mode === "scanner-single") return "Scanner + agent fusion";
  if (mode === "scanner-moa-low") return "Scanner + three specialists";
  if (mode === "scanner-moa-high") return "Scanner + five specialists";
  return "Scan mode";
}

function inferParentStageId(event: ScanProgressEvent): string | undefined {
  if (timelineStageIds.has(event.id) || event.id === "scan-assist-mode") {
    return undefined;
  }

  const text = `${event.id} ${event.label} ${event.message ?? ""}`.toLowerCase();
  if (/(candidate|focused|task|evidence|revalid|checkpoint|resume|judge|aggregat|specialist|agent)/.test(text)) {
    return "model-summary";
  }
  if (/(pdf|artifact|dashboard|one-page|onepager|report)/.test(text)) {
    return "report-ready";
  }
  if (/(scanner|semgrep|gitleaks|bandit|osv|pmg|heuristic|intelligence)/.test(text)) {
    return "running-scans";
  }
  return undefined;
}

function eventToDetails(event: ScanProgressEvent): ScanProgressDetail[] {
  const summary = compactDetailValue(event.details);
  const primary: ScanProgressDetail = {
    id: event.id,
    label: event.label,
    status: event.status,
    message: event.message,
  };
  if (summary) {
    primary.value = summary;
  }

  const countDetails = (event.details ?? [])
    .filter((detail) => isCountDetail(detail))
    .map((detail) => ({
      ...detail,
      id: `${event.id}:${detail.id ?? detail.label}`,
      label: `${event.label}: ${detail.label}`,
      status: detail.status ?? event.status,
    }));

  return [primary, ...countDetails];
}

function compactDetailValue(details: ScanProgressDetail[] | undefined): string | undefined {
  if (!details?.length) return undefined;

  const accepted = detailValue(details, /accepted/i);
  const rejected = detailValue(details, /rejected/i);
  const review = detailValue(details, /needs.*review|review/i);
  if (accepted || rejected || review) {
    return [
      accepted ? `${accepted} accepted` : "",
      rejected ? `${rejected} rejected` : "",
      review ? `${review} review` : "",
    ].filter(Boolean).join(", ");
  }

  const candidates = detailValue(details, /candidate/i);
  if (candidates) return `${candidates} candidates`;
  const findings = detailValue(details, /finding|final/i);
  if (findings) return `${findings} findings`;
  const duration = detailValue(details, /duration|runtime/i);
  if (duration) return duration;
  return details.find((detail) => detail.value)?.value;
}

function detailValue(details: ScanProgressDetail[], pattern: RegExp): string | undefined {
  return details.find((detail) => pattern.test(detail.label) && detail.value)?.value;
}

function isCountDetail(detail: ScanProgressDetail): boolean {
  return Boolean(detail.value && /(candidate|accepted|rejected|review|finding|final)/i.test(detail.label));
}

function dedupeDetails(details: ScanProgressDetail[]): ScanProgressDetail[] {
  const byKey = new Map<string, ScanProgressDetail>();
  for (const detail of details) {
    byKey.set(detail.id ?? detail.label, detail);
  }
  return Array.from(byKey.values());
}

function valueForStage(event: ScanProgressEvent | undefined): string | undefined {
  if (!event) return undefined;
  if (event.status === "running") return "now";
  if (event.status === "completed") return "done";
  if (event.status === "skipped") return "skipped";
  if (event.status === "failed") return "failed";
  return undefined;
}

function stageDuration(stage: { timestamp?: number; status: ScanProgressStatus }) {
  if (!stage.timestamp || stage.status === "waiting") return "";
  return new Date(stage.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}
