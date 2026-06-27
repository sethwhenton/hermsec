import { motion } from "framer-motion";
import { Bot, GitMerge, Network, Radar } from "lucide-react";
import { useId } from "react";
import { cn } from "@/lib/cn";
import { normalizeScanAssistMode, scanModeOptions } from "@/lib/scanModes";
import type { HermsecProductScanAssistMode, HermsecVisibleScanAssistMode } from "@/types/scan";

interface ScanModeSegmentedControlProps {
  value: HermsecProductScanAssistMode;
  onChange: (value: HermsecProductScanAssistMode) => void;
  compact?: boolean;
  disabled?: boolean;
}

const modeIcons = {
  "deep-assisted": Radar,
  "single-agent": Bot,
  "moa-assisted": Network,
  "scanner-moa-assisted": GitMerge,
} satisfies Record<HermsecVisibleScanAssistMode, typeof Radar>;

export function ScanModeSegmentedControl({
  value,
  onChange,
  compact = false,
  disabled = false,
}: ScanModeSegmentedControlProps) {
  const controlId = useId();
  const normalizedValue = normalizeScanAssistMode(value);

  return (
    <div
      className={cn(
        "grid gap-1 rounded-xl border border-border bg-background p-1",
        compact ? "grid-cols-2" : "grid-cols-2 xl:grid-cols-4",
      )}
      role="radiogroup"
      aria-label="Scan assist mode"
    >
      {scanModeOptions.map((option) => {
        const Icon = modeIcons[option.id];
        const selected = normalizedValue === option.id;
        return (
          <button
            key={option.id}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={disabled}
            onClick={() => onChange(option.id)}
            className={cn(
              "relative min-w-0 rounded-lg px-2.5 py-2 text-left transition-colors duration-150 ease-out focus:outline-none focus:ring-2 focus:ring-accent/40",
              selected ? "text-foreground" : "text-muted hover:bg-white/[0.04] hover:text-foreground",
              disabled && "pointer-events-none opacity-60",
            )}
          >
            {selected ? (
              <motion.span
                layoutId={`scan-mode-segment-${controlId}`}
                className="absolute inset-0 rounded-lg border border-accent/35 bg-accent-muted shadow-[0_8px_24px_rgba(0,0,0,0.18)]"
                transition={{ type: "spring", stiffness: 520, damping: 38 }}
              />
            ) : null}
            <span className="relative flex items-start gap-2">
              <span
                className={cn(
                  "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border",
                  selected ? "border-accent/35 bg-accent/15 text-accent" : "border-border bg-surface-elevated",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="min-w-0">
                <span className="block truncate text-xs font-semibold">
                  {compact ? option.shortLabel : option.label}
                </span>
                {!compact ? (
                  <span className="mt-0.5 block text-[11px] leading-4 text-muted">{option.status}</span>
                ) : null}
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
