import { cn } from "@/lib/cn";

type BadgeVariant = "default" | "muted" | "success" | "danger";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const variants: Record<BadgeVariant, string> = {
  default: "bg-white/10 text-foreground",
  muted: "bg-surface-elevated text-muted",
  success: "bg-success/15 text-success",
  danger: "bg-danger/15 text-danger",
};

export function Badge({ children, variant = "muted", className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
