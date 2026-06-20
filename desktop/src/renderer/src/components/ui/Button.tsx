import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

type ButtonVariant = "default" | "ghost" | "outline" | "danger" | "subtle";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md" | "icon";
}

const variantClasses: Record<ButtonVariant, string> = {
  default: "bg-foreground text-background hover:bg-foreground/90",
  ghost: "bg-transparent text-foreground hover:bg-white/5",
  outline: "border border-border bg-transparent text-foreground hover:bg-white/5",
  danger: "bg-danger/10 text-danger hover:bg-danger/20",
  subtle: "bg-surface-elevated text-muted hover:text-foreground hover:bg-white/5",
};

const sizeClasses = {
  sm: "h-7 px-2.5 text-xs rounded-md",
  md: "h-8 px-3 text-sm rounded-md",
  icon: "h-7 w-7 rounded-md",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "md", type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 font-medium transition-colors active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none no-drag",
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    />
  ),
);

Button.displayName = "Button";
