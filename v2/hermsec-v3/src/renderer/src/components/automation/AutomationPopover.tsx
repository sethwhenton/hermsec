import { Clock, PlayCircle, X } from "lucide-react";
import { useState } from "react";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { Button } from "@/components/ui/Button";
import type { AutomationFrequency } from "@/types/settings";

interface AutomationPopoverProps {
  open: boolean;
  onClose: () => void;
}

const frequencyOptions: Array<{ value: AutomationFrequency; label: string }> = [
  { value: "daily", label: "Every day" },
  { value: "every-3-days", label: "Every 3 days" },
  { value: "weekly", label: "Every week" },
];

export function AutomationPopover({ open, onClose }: AutomationPopoverProps) {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const runScan = useReportStore((s) => s.runScan);
  const latestReport = useReportStore((s) => s.latestReport);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const [frequency, setFrequency] = useState<AutomationFrequency>(settings?.automation.frequency ?? "daily");
  const [time, setTime] = useState(settings?.automation.time ?? "09:00");
  const [enabled, setEnabled] = useState(settings?.automation.enabled ?? false);

  if (!open) return null;

  const save = async () => {
    await updateSettings({
      automation: {
        enabled,
        frequency,
        time,
      },
    });
    onClose();
  };

  const runNow = async () => {
    const result = await runScan({
      targetPath: settings?.defaultProjectDir,
      reportDir: settings?.defaultReportDir,
      mode: "online",
      useModel: true,
      skipIfUnchanged: true,
      previousProjectState: latestReport?.projectState,
    });
    await updateSettings({
      automation: {
        ...settings?.automation,
        enabled,
        frequency,
        time,
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
        <div className="grid grid-cols-3 gap-1">
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
