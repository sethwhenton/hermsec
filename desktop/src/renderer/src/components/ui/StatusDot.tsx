import { cn } from "@/lib/cn";

type Status = "idle" | "active" | "success" | "warning" | "error";

interface StatusDotProps {
  status: Status;
  className?: string;
}

const statusColors: Record<Status, string> = {
  idle: "bg-muted",
  active: "bg-accent",
  success: "bg-success",
  warning: "bg-amber-400",
  error: "bg-danger",
};

export function StatusDot({ status, className }: StatusDotProps) {
  return (
    <span
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", statusColors[status], className)}
    />
  );
}
