import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";

const initialActions = ["Scan project", "Check system health", "About"] as const;
const reportActions = ["Scan project", "Check system health", "About", "Generate prompt"] as const;

interface QuickActionsProps {
  onAction: (action: string) => void;
  hasReport?: boolean;
  compact?: boolean;
  className?: string;
}

export function QuickActions({ onAction, hasReport = false, compact, className }: QuickActionsProps) {
  const actions = hasReport ? reportActions : initialActions;

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
