import { cn } from "~/lib/utils";

const QUICK_ACTIONS = [
  { id: "scan", label: "Scan repo" },
  { id: "explain", label: "Explain project" },
  { id: "doctor", label: "Doctor" },
  { id: "reports", label: "Reports" },
  { id: "automations", label: "Automations" },
] as const;

type HermsecQuickActionBarProps = {
  onAction?: (actionId: (typeof QUICK_ACTIONS)[number]["id"]) => void;
};

export function HermsecQuickActionBar({ onAction }: HermsecQuickActionBarProps) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-1.5">
      {QUICK_ACTIONS.map((action) => (
        <button
          key={action.id}
          type="button"
          onClick={() => onAction?.(action.id)}
          className={cn(
            "rounded-md border border-[color:var(--color-border)] px-2.5 py-1",
            "text-[length:var(--app-font-size-ui,12px)] text-muted-foreground/80",
            "transition-colors hover:border-[color:color-mix(in_srgb,var(--foreground)_12%,transparent)]",
            "hover:bg-white/[0.03] hover:text-foreground/85",
          )}
        >
          {action.label}
        </button>
      ))}
    </div>
  );
}
