import { cn } from "@/lib/cn";

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}

export function Toggle({ checked, onChange, disabled, className }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "no-drag relative h-5 w-9 rounded-full transition-colors",
        checked ? "bg-foreground" : "bg-border",
        disabled && "opacity-40",
        className,
      )}
    >
      <span
        className={cn(
          "absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-background transition-transform",
          checked && "translate-x-4",
        )}
      />
    </button>
  );
}
