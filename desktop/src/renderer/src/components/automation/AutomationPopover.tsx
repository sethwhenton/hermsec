import { Clock, PlayCircle, X } from "lucide-react";
import { useState } from "react";
import { normalizeScanAssistMode } from "@/lib/scanModes";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { ScanModeSegmentedControl } from "@/components/scan/ScanModeSegmentedControl";
import { Button } from "@/components/ui/Button";
import type { HermsecProductScanAssistMode } from "@/types/scan";
import type { AutomationFrequency } from "@/types/settings";

interface AutomationPopoverProps {
  open: boolean;
  onClose: () => void;
}

const frequencyOptions: Array<{ value: Extract<AutomationFrequency, "weekly" | "monthly">; label: string }> = [
  { value: "weekly", label: "Every week" },
  { value: "monthly", label: "Every month" },
];

export function AutomationPopover({ open, onClose }: AutomationPopoverProps) {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const runScan = useReportStore((s) => s.runScan);
  const latestReport = useReportStore((s) => s.latestReport);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const [frequency, setFrequency] = useState<AutomationFrequency>(
    normalizeFrequency(settings?.automation.frequency),
  );
  const [intervalDays, setIntervalDays] = useState(settings?.automation.intervalDays ?? 1);
  const [time, setTime] = useState(settings?.automation.time ?? "09:00");
  const [enabled, setEnabled] = useState(settings?.automation.enabled ?? false);
  const [scanMode, setScanMode] = useState<HermsecProductScanAssistMode>(
    normalizeScanAssistMode(settings?.automation.scanMode ?? settings?.general.scanMode),
  );

  if (!open) return null;

  const save = async () => {
    await updateSettings({
      automation: {
        ...settings?.automation,
        enabled,
        frequency,
        intervalDays: normalizeIntervalDays(intervalDays),
        time,
        scanMode,
      },
    });
    onClose();
  };

  const runNow = async () => {
    const result = await runScan({
      targetPath: settings?.defaultProjectDir,
      reportDir: settings?.defaultReportDir,
      mode: "online",
      assistMode: scanMode,
      useModel: true,
      skipIfUnchanged: true,
      previousProjectState: latestReport?.projectState,
    });
    await updateSettings({
      automation: {
        ...settings?.automation,
        enabled,
        frequency,
        intervalDays: normalizeIntervalDays(intervalDays),
        time,
        scanMode,
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
    <div className="absolute right-0 top-9 z-50 w-[340px] rounded-xl border border-border bg-surface-elevated p-4 shadow-[0_22px_70px_rgba(0,0,0,0.45)]">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-accent" />
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
            className={`h-9 rounded-md border px-3 text-xs transition-colors ${
              frequency === "custom-days"
                ? "border-accent bg-accent-muted text-foreground"
                : "border-border bg-surface-elevated text-muted hover:text-foreground"
            }`}
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
          {frequencyOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              className={`rounded-md border px-2 py-2 text-xs transition-colors ${
                frequency === option.value
                  ? "border-accent bg-accent-muted text-foreground"
                  : "border-border bg-background text-muted hover:text-foreground"
              }`}
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
          <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-muted">tokens vary</span>
        </div>
        <ScanModeSegmentedControl value={scanMode} onChange={setScanMode} compact />
      </div>

      <div className="mb-4 rounded-lg border border-border bg-background p-3 text-xs text-muted">
        Last result: {settings?.automation.lastResult ?? "No automation run yet."}
      </div>

      <div className="flex items-center justify-between gap-2">
        <Button variant="outline" size="sm" disabled={scanRunning} onClick={() => void runNow()}>
          <PlayCircle className="h-3.5 w-3.5" />
          Run now
        </Button>
        <Button size="sm" onClick={() => void save()}>
          Save automation
        </Button>
      </div>
    </div>
  );
}

function normalizeFrequency(frequency: AutomationFrequency | undefined): AutomationFrequency {
  if (frequency === "weekly" || frequency === "monthly") return frequency;
  return "custom-days";
}

function normalizeIntervalDays(value: number | undefined): number {
  if (!Number.isFinite(Number(value))) return 1;
  return Math.min(365, Math.max(1, Math.floor(Number(value))));
}
