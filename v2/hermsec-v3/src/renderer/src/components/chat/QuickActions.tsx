import { Button } from "@/components/ui/Button";

const actions = [
  "Scan project",
  "Explain project",
  "Doctor",
  "Reports",
  "Automations",
] as const;

interface QuickActionsProps {
  onAction: (action: string) => void;
}

export function QuickActions({ onAction }: QuickActionsProps) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-1.5">
      {actions.map((action) => (
        <Button key={action} variant="subtle" size="sm" onClick={() => onAction(action)}>
          {action}
        </Button>
      ))}
    </div>
  );
}
