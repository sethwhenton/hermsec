import { Clock, Edit3, MoreHorizontal, Play, X } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/cn";
import { normalizeScanAssistMode, scanModeLabel } from "@/lib/scanModes";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ScanModeSegmentedControl } from "@/components/scan/ScanModeSegmentedControl";
import { Button } from "@/components/ui/Button";
import type { HermsecScanAssistMode } from "@/types/scan";
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

  const runNow = async (assistModeOverride?: HermsecScanAssistMode) => {
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
    <div className="h-full overflow-y-auto bg-background px-8 py-10">
      <div className="mx-auto w-full max-w-[760px]">
        <div className="mb-10 flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[1.75rem] font-medium tracking-tight text-foreground">Automations</h1>
          </div>
          <button
            type="button"
            className="rounded-full border border-border bg-foreground px-3 py-1.5 text-xs font-medium text-background transition-colors hover:bg-foreground/90 active:scale-[0.98]"
            onClick={() => setView("chat")}
          >
            Create via chat
          </button>
        </div>

        <section>
          <div className="mb-3 border-b border-border-subtle pb-3 text-sm font-semibold text-foreground">
            Current
          </div>
          <div className="group/automation relative rounded-xl">
            <button
              type="button"
              className="flex w-full items-center gap-3 rounded-xl py-3 pl-2 pr-28 text-left transition-colors duration-150 ease-out hover:bg-white/7"
              onClick={() => setEditorOpen(true)}
            >
              <span
                className={cn(
                  "h-3.5 w-3.5 shrink-0 rounded-full",
                  automation.enabled ? "bg-accent" : "bg-muted-foreground",
                )}
              />
              <span className="min-w-0 flex-1">
                <span className="text-sm font-medium text-foreground">Hermsec project scan</span>
                <span className="ml-2 text-sm text-muted">{projectName}</span>
              </span>
              <span className="hidden shrink-0 text-xs text-muted transition-opacity duration-150 ease-out group-hover/automation:opacity-0 md:inline">
                {statusLabel}
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
  onRunNow: (assistMode?: HermsecScanAssistMode) => Promise<void>;
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
  const [scanMode, setScanMode] = useState<HermsecScanAssistMode>(
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
    <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/50 px-4 backdrop-blur-sm">
      <div className="w-full max-w-[440px] rounded-2xl border border-border bg-surface-elevated p-4 shadow-[0_22px_80px_rgba(0,0,0,0.48)]">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <Clock className="mt-0.5 h-4 w-4 text-accent" />
            <div>
              <div className="text-sm font-medium text-foreground">Automation</div>
              <div className="text-xs text-muted">Runs only while Hermsec is open.</div>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>

        <label className="mb-3 flex items-center justify-between rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
          Enabled
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
            className="h-4 w-4 accent-[var(--color-accent)]"
          />
        </label>

        <div className="mb-3">
          <div className="mb-1 text-xs text-muted">Frequency</div>
          <div className="mb-2 flex items-center gap-2 rounded-lg border border-border bg-background p-2">
            <button
              type="button"
              className={cn(
                "h-9 rounded-md border px-3 text-xs transition-colors",
                frequency === "custom-days"
                  ? "border-accent bg-accent-muted text-foreground"
                  : "border-border bg-surface-elevated text-muted hover:text-foreground",
              )}
              onClick={() => setFrequency("custom-days")}
            >
              Every
            </button>
            <input
              type="number"
              min={1}
              max={365}
              value={intervalDays}
              onFocus={() => setFrequency("custom-days")}
              onChange={(event) => setIntervalDays(normalizeIntervalDays(Number(event.target.value)))}
              className="h-9 w-20 rounded-md border border-border bg-surface-elevated px-3 text-sm text-foreground outline-none focus:border-accent"
              aria-label="Automation interval in days"
            />
            <span className="text-xs text-muted">{normalizeIntervalDays(intervalDays) === 1 ? "Day" : "Days"}</span>
          </div>
          <div className="grid grid-cols-2 gap-1">
            {[
              { value: "weekly" as const, label: "Every week" },
              { value: "monthly" as const, label: "Every month" },
            ].map((option) => (
              <button
                key={option.value}
                type="button"
                className={cn(
                  "rounded-md border px-2 py-2 text-xs transition-colors",
                  frequency === option.value
                    ? "border-accent bg-accent-muted text-foreground"
                    : "border-border bg-background text-muted hover:text-foreground",
                )}
                onClick={() => setFrequency(option.value)}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        <label className="mb-4 block">
          <div className="mb-1 text-xs text-muted">Exact time</div>
          <input
            type="time"
            value={time}
            onChange={(event) => setTime(event.target.value)}
            className="h-9 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-accent"
          />
        </label>

        <div className="mb-4">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-xs text-muted">Scan assist mode</span>
            <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-muted">per run</span>
          </div>
          <ScanModeSegmentedControl value={scanMode} onChange={setScanMode} />
        </div>

        <div className="mb-4 rounded-lg border border-border bg-background p-3 text-xs text-muted">
          Last result: {settings.automation.lastResult ?? "No automation run yet."}
        </div>

        <div className="flex items-center justify-between gap-2">
          <Button variant="outline" size="sm" disabled={scanRunning} onClick={() => void onRunNow(scanMode)}>
            <Play className="h-3.5 w-3.5" />
            Run now
          </Button>
          <Button size="sm" onClick={() => void save()}>
            Save automation
          </Button>
        </div>
      </div>
    </div>
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
