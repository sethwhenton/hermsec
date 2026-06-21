import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";

const actions = [
  "Scan project",
  "Explain project",
  "Doctor",
  "Reports",
  "Automations",
] as const;

interface QuickActionsProps {
  onAction: (action: string) => void;
  compact?: boolean;
  className?: string;
}

export function QuickActions({ onAction, compact, className }: QuickActionsProps) {
  return (
    <div className={cn("flex flex-wrap items-center justify-center gap-1.5", className)}>
      {actions.map((action) => (
        <Button
          key={action}
          variant="subtle"
          size="sm"
          className={compact ? "h-7 px-2.5 text-[11px]" : undefined}
          onClick={() => onAction(action)}
        >
          {action}
        </Button>
      ))}
    </div>
  );
}
