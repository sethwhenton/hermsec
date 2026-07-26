import { CalendarClock, CheckCircle2, Clock, PlayCircle, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { normalizeScanAssistMode, scanModeRequiresModel } from "@/lib/scanModes";
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
  const reduceMotion = useReducedMotion();

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
      useModel: scanModeRequiresModel(scanMode),
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

  const normalizedDays = normalizeIntervalDays(intervalDays);
  const scheduleText = enabled
    ? `${formatFrequencyLabel(frequency, normalizedDays)} at ${formatClockTime(time)}`
    : "Paused until you enable it";

  return (
    <AnimatePresence initial={false}>
      {open && (
        <motion.div
          className="absolute right-0 top-10 z-50 w-[min(380px,calc(100vw-24px))] origin-top-right overflow-hidden rounded-[24px] border border-border/80 bg-surface-elevated/95 text-foreground shadow-[0_24px_90px_rgba(0,0,0,0.52)] backdrop-blur will-change-[opacity,transform]"
          initial={reduceMotion ? { opacity: 0 } : { opacity: 0, scale: 0.975, y: -6 }}
          animate={reduceMotion ? { opacity: 1 } : { opacity: 1, scale: 1, y: 0 }}
          exit={reduceMotion ? { opacity: 0 } : { opacity: 0, scale: 0.985, y: -4 }}
          transition={
            reduceMotion
              ? { duration: 0.01 }
              : { duration: 0.16, ease: [0.23, 1, 0.32, 1] }
          }
        >
      <div className="h-px bg-gradient-to-r from-transparent via-foreground/20 to-transparent" />
      <div className="max-h-[calc(100vh-72px)] overflow-y-auto p-4">
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
            <span className="mt-0.5 block truncate text-xs text-muted">{scheduleText}</span>
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
              <span className="pr-1 text-xs text-muted">{normalizedDays === 1 ? "day" : "days"}</span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {frequencyOptions.map((option) => (
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
            <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">tokens vary</span>
          </div>
          <ScanModeSegmentedControl value={scanMode} onChange={setScanMode} compact />
        </div>

        <div className="mb-4 rounded-[16px] border border-border/70 bg-background/60 px-3 py-2.5 text-xs text-muted shadow-inner">
          <span className="text-muted-foreground">Last result</span>
          <div className="mt-1 line-clamp-2 text-foreground/85">
            {settings?.automation.lastResult ?? "No automation run yet."}
          </div>
        </div>

        <div className="flex items-center justify-between gap-2">
          <Button variant="outline" size="sm" disabled={scanRunning} onClick={() => void runNow()} className="rounded-full">
            <PlayCircle className="h-3.5 w-3.5" />
            Run now
          </Button>
          <Button size="sm" onClick={() => void save()} className="rounded-full px-3">
            Save automation
          </Button>
        </div>
      </div>
        </motion.div>
      )}
    </AnimatePresence>
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

function formatFrequencyLabel(frequency: AutomationFrequency, intervalDays: number): string {
  if (frequency === "weekly") return "Every week";
  if (frequency === "monthly") return "Every month";
  return intervalDays === 1 ? "Every day" : `Every ${intervalDays} days`;
}

function formatClockTime(value: string): string {
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
