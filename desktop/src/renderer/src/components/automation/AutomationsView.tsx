import { CalendarClock, CheckCircle2, Clock, Edit3, MoreHorizontal, Play, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { normalizeScanAssistMode, scanModeLabel } from "@/lib/scanModes";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ScanModeSegmentedControl } from "@/components/scan/ScanModeSegmentedControl";
import { Button } from "@/components/ui/Button";
import type { HermsecProductScanAssistMode } from "@/types/scan";
import type { AutomationFrequency } from "@/types/settings";

export function AutomationsView() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const setView = useUiStore((s) => s.setView);
  const runScan = useReportStore((s) => s.runScan);
  const latestReport = useReportStore((s) => s.latestReport);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const [editorOpen, setEditorOpen] = useState(false);

  if (!settings) return null;

  const automation = settings.automation;
  const currentScanMode = normalizeScanAssistMode(automation.scanMode ?? settings.general.scanMode);
  const projectName = settings.defaultProjectDir ? folderName(settings.defaultProjectDir) : "No project selected";
  const schedule = `${formatFrequency(automation)} at ${formatTime(automation.time)}`;
  const statusLabel = automation.enabled ? `${schedule} - ${scanModeLabel(currentScanMode)}` : "Disabled";

  const runNow = async (assistModeOverride?: HermsecProductScanAssistMode) => {
    const assistMode = normalizeScanAssistMode(assistModeOverride ?? automation.scanMode ?? settings.general.scanMode);
    const result = await runScan({
      targetPath: settings.defaultProjectDir,
      reportDir: settings.defaultReportDir,
      mode: "online",
      assistMode,
      useModel: true,
      skipIfUnchanged: true,
      previousProjectState: latestReport?.projectState,
    });
    await updateSettings({
      automation: {
        ...automation,
        scanMode: assistMode,
        lastCheckedAt: new Date().toISOString(),
        lastResult: result.unchanged ? "No project changes since the last scan." : result.message,
        ...(result.projectState?.fingerprint
          ? { lastProjectStateFingerprint: result.projectState.fingerprint }
          : {}),
        ...(result.reportDir ? { lastReportDir: result.reportDir } : {}),
        ...(!result.unchanged ? { lastRunAt: new Date().toISOString() } : {}),
      },
    });
  };

  return (
    <div className="h-full overflow-y-auto bg-background px-6 py-8 sm:px-8 sm:py-10">
      <div className="mx-auto w-full max-w-[760px]">
        <div className="mb-9 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[1.75rem] font-medium tracking-tight text-foreground">Automations</h1>
            <p className="mt-1 max-w-[48ch] text-sm leading-5 text-muted">
              Change-aware scans that run while Hermsec is open.
            </p>
          </div>
          <button
            type="button"
            className="shrink-0 rounded-full border border-border bg-foreground px-3 py-1.5 text-xs font-medium text-background transition-colors duration-150 ease-out hover:bg-foreground/90 active:scale-[0.98]"
            onClick={() => setView("chat")}
          >
            Create via chat
          </button>
        </div>

        <section>
          <div className="mb-3 flex items-center justify-between border-b border-border-subtle pb-3">
            <div className="text-sm font-semibold text-foreground">Current</div>
            <div className="text-xs text-muted">{automation.enabled ? "Enabled" : "Paused"}</div>
          </div>
          <div className="group/automation relative rounded-2xl border border-border/70 bg-surface-elevated/45 p-1 shadow-[0_16px_60px_rgba(0,0,0,0.18)]">
            <button
              type="button"
              className="flex w-full items-center gap-3 rounded-xl px-3 py-3 pr-28 text-left transition-colors duration-150 ease-out hover:bg-white/[0.06]"
              onClick={() => setEditorOpen(true)}
            >
              <span
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border",
                  automation.enabled
                    ? "border-accent/35 bg-accent/10 text-accent"
                    : "border-border bg-background text-muted",
                )}
              >
                <Clock className="h-4 w-4" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="text-sm font-medium text-foreground">Hermsec project scan</span>
                <span className="ml-2 text-sm text-muted">{projectName}</span>
                <span className="mt-0.5 block truncate text-xs text-muted-foreground">{statusLabel}</span>
              </span>
              <span className="hidden shrink-0 rounded-full border border-border/70 bg-background/70 px-2 py-1 text-xs text-muted transition-opacity duration-150 ease-out group-hover/automation:opacity-0 md:inline">
                {formatTime(automation.time)}
              </span>
            </button>

            <div className="pointer-events-none absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-1 opacity-0 transition-opacity duration-150 ease-out group-hover/automation:pointer-events-auto group-hover/automation:opacity-100">
              <button
                type="button"
                className="flex h-7 w-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-white/8 hover:text-foreground active:scale-[0.97]"
                title="Run now"
                disabled={scanRunning}
                onClick={(event) => {
                  event.stopPropagation();
                  void runNow();
                }}
              >
                <Play className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                className="flex h-7 w-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-white/8 hover:text-foreground active:scale-[0.97]"
                title="Edit automation"
                onClick={(event) => {
                  event.stopPropagation();
                  setEditorOpen(true);
                }}
              >
                <Edit3 className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                className="flex h-7 w-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-white/8 hover:text-foreground active:scale-[0.97]"
                title="More"
                onClick={(event) => {
                  event.stopPropagation();
                  setEditorOpen(true);
                }}
              >
                <MoreHorizontal className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </section>
      </div>

      {editorOpen ? (
        <AutomationEditorDialog
          onClose={() => setEditorOpen(false)}
          onRunNow={runNow}
          scanRunning={scanRunning}
        />
      ) : null}
    </div>
  );
}

function AutomationEditorDialog({
  onClose,
  onRunNow,
  scanRunning,
}: {
  onClose: () => void;
  onRunNow: (assistMode?: HermsecProductScanAssistMode) => Promise<void>;
  scanRunning: boolean;
}) {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const [frequency, setFrequency] = useState<AutomationFrequency>(
    normalizeFrequency(settings?.automation.frequency),
  );
  const [intervalDays, setIntervalDays] = useState(settings?.automation.intervalDays ?? 1);
  const [time, setTime] = useState(settings?.automation.time ?? "09:00");
  const [enabled, setEnabled] = useState(settings?.automation.enabled ?? false);
  const [scanMode, setScanMode] = useState<HermsecProductScanAssistMode>(
    normalizeScanAssistMode(settings?.automation.scanMode ?? settings?.general.scanMode),
  );

  if (!settings) return null;

  const save = async () => {
    await updateSettings({
      automation: {
        ...settings.automation,
        enabled,
        frequency,
        intervalDays: normalizeIntervalDays(intervalDays),
        time,
        scanMode,
      },
    });
    onClose();
  };

  return (
    <div className="absolute inset-0 z-50 overflow-y-auto bg-background/58 px-4 py-8 backdrop-blur-sm sm:py-12">
      <div className="mx-auto w-full max-w-[460px] overflow-hidden rounded-[24px] border border-border/80 bg-surface-elevated/95 text-foreground shadow-[0_24px_90px_rgba(0,0,0,0.52)] backdrop-blur">
        <div className="h-px bg-gradient-to-r from-transparent via-foreground/20 to-transparent" />
        <div className="max-h-[calc(100vh-64px)] overflow-y-auto p-4">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-border/80 bg-background/70 text-accent shadow-[0_10px_30px_rgba(0,0,0,0.28)]">
                <CalendarClock className="h-4 w-4" />
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <div className="text-sm font-semibold tracking-normal text-foreground">Automation</div>
                  <span
                    className={cn(
                      "rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                      enabled
                        ? "border-accent/35 bg-accent/10 text-accent"
                        : "border-border bg-background/70 text-muted",
                    )}
                  >
                    {enabled ? "On" : "Off"}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-muted">Runs only while Hermsec is open.</div>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} className="-mr-1 -mt-1 shrink-0 rounded-full">
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>

          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            className="mb-4 flex w-full items-center justify-between gap-3 rounded-[18px] border border-border/80 bg-background/65 px-3 py-3 text-left shadow-inner transition-colors duration-150 ease-out hover:border-foreground/20 active:scale-[0.99]"
            onClick={() => setEnabled((value) => !value)}
          >
            <span className="min-w-0">
              <span className="block text-sm font-medium text-foreground">Scheduled scans</span>
              <span className="mt-0.5 block truncate text-xs text-muted">
                {enabled ? `${formatFrequency({ frequency, intervalDays })} at ${formatTime(time)}` : "Paused until you enable it"}
              </span>
            </span>
            <span
              className={cn(
                "relative h-6 w-11 shrink-0 rounded-full border transition-colors duration-150 ease-out",
                enabled ? "border-accent/45 bg-accent/25" : "border-border bg-surface",
              )}
            >
              <span
                className={cn(
                  "absolute top-1/2 flex h-4.5 w-4.5 -translate-y-1/2 items-center justify-center rounded-full bg-foreground text-background shadow-[0_5px_14px_rgba(0,0,0,0.35)] transition-transform duration-150 ease-out",
                  enabled ? "translate-x-[21px]" : "translate-x-0.5",
                )}
              >
                {enabled ? <CheckCircle2 className="h-3 w-3" /> : null}
              </span>
            </span>
          </button>

          <div className="mb-4">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs font-medium text-muted">Frequency</span>
              <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">change-aware</span>
            </div>
            <div className="rounded-[18px] border border-border/80 bg-background/70 p-2 shadow-inner">
              <div className="mb-2 grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2">
                <FrequencyButton selected={frequency === "custom-days"} onClick={() => setFrequency("custom-days")}>
                  Every
                </FrequencyButton>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={intervalDays}
                  onFocus={() => setFrequency("custom-days")}
                  onChange={(event) => setIntervalDays(normalizeIntervalDays(Number(event.target.value)))}
                  className="h-10 min-w-0 rounded-xl border border-border/80 bg-surface-elevated/90 px-3 text-sm text-foreground outline-none transition-colors duration-150 ease-out focus:border-accent/70"
                  aria-label="Automation interval in days"
                />
                <span className="pr-1 text-xs text-muted">
                  {normalizeIntervalDays(intervalDays) === 1 ? "day" : "days"}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {[
                  { value: "weekly" as const, label: "Every week" },
                  { value: "monthly" as const, label: "Every month" },
                ].map((option) => (
                  <FrequencyButton
                    key={option.value}
                    selected={frequency === option.value}
                    onClick={() => setFrequency(option.value)}
                    wide
                  >
                    {option.label}
                  </FrequencyButton>
                ))}
              </div>
            </div>
          </div>

          <label className="mb-4 block">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs font-medium text-muted">Exact time</span>
              <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">local</span>
            </div>
            <div className="relative">
              <input
                type="time"
                value={time}
                onChange={(event) => setTime(event.target.value)}
                className="h-11 w-full rounded-[16px] border border-border/80 bg-background/70 px-3 pr-10 text-sm font-medium text-foreground outline-none shadow-inner transition-colors duration-150 ease-out focus:border-accent/70"
              />
              <Clock className="pointer-events-none absolute right-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            </div>
          </label>

          <div className="mb-4">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs font-medium text-muted">Scan assist mode</span>
              <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">per run</span>
            </div>
            <ScanModeSegmentedControl value={scanMode} onChange={setScanMode} compact />
          </div>

          <div className="mb-4 rounded-[16px] border border-border/70 bg-background/60 px-3 py-2.5 text-xs text-muted shadow-inner">
            <span className="text-muted-foreground">Last result</span>
            <div className="mt-1 line-clamp-2 text-foreground/85">
              {settings.automation.lastResult ?? "No automation run yet."}
            </div>
          </div>

          <div className="flex items-center justify-between gap-2">
            <Button variant="outline" size="sm" disabled={scanRunning} onClick={() => void onRunNow(scanMode)} className="rounded-full">
              <Play className="h-3.5 w-3.5" />
              Run now
            </Button>
            <Button size="sm" onClick={() => void save()} className="rounded-full px-3">
              Save automation
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function FrequencyButton({
  selected,
  onClick,
  children,
  wide = false,
}: {
  selected: boolean;
  onClick: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <button
      type="button"
      className={cn(
        "h-10 rounded-xl border px-3 text-xs font-medium transition-colors duration-150 ease-out active:scale-[0.98]",
        wide ? "w-full" : "",
        selected
          ? "border-accent/55 bg-accent-muted text-foreground shadow-[0_8px_24px_rgba(0,0,0,0.2)]"
          : "border-border/80 bg-surface-elevated/75 text-muted hover:border-foreground/20 hover:text-foreground",
      )}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function formatFrequency(automation: { frequency: string; intervalDays?: number }): string {
  if (automation.frequency === "weekly") return "Every week";
  if (automation.frequency === "monthly") return "Every month";
  const days = normalizeIntervalDays(automation.intervalDays);
  return days === 1 ? "Every day" : `Every ${days} days`;
}

function formatTime(value: string): string {
  const [hourText, minuteText] = value.split(":");
  const hours = Number(hourText);
  const minutes = Number(minuteText);
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return value;
  const suffix = hours >= 12 ? "PM" : "AM";
  const hour12 = hours % 12 || 12;
  return `${hour12}:${String(minutes).padStart(2, "0")} ${suffix}`;
}

function normalizeFrequency(frequency: AutomationFrequency | undefined): AutomationFrequency {
  if (frequency === "weekly" || frequency === "monthly") return frequency;
  return "custom-days";
}

function normalizeIntervalDays(value: number | undefined): number {
  if (!Number.isFinite(Number(value))) return 1;
  return Math.min(365, Math.max(1, Math.floor(Number(value))));
}

function folderName(filePath: string): string {
  const parts = filePath.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) ?? "Project";
}
