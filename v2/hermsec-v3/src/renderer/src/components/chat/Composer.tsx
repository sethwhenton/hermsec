import { ArrowUp } from "lucide-react";
import { useRef, useState, type KeyboardEvent } from "react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/Button";
import { ContextBar } from "./ContextBar";

interface ComposerProps {
  onSend: (text: string) => void;
  disabled?: boolean;
  className?: string;
}

export function Composer({ onSend, disabled, className }: ComposerProps) {
  const [value, setValue] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSend = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setValue("");
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSend();
    }
  };

  const handleInput = () => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  };

  return (
    <div
      className={cn(
        "rounded-[var(--radius-lg)] border border-border bg-surface-elevated p-3 shadow-[0_12px_40px_rgba(0,0,0,0.45)]",
        className,
      )}
    >
      <textarea
        ref={textareaRef}
        value={value}
        disabled={disabled}
        onChange={(e) => setValue(e.target.value)}
        onInput={handleInput}
        onKeyDown={handleKeyDown}
        placeholder="Do anything"
        rows={1}
        className="no-drag mb-2 w-full resize-none bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none"
      />
      <div className="mb-2">
        <ContextBar />
      </div>
      <div className="flex items-center justify-between">
        <div />
        <Button
          size="icon"
          className="rounded-full"
          disabled={!value.trim() || disabled}
          onClick={handleSend}
        >
          <ArrowUp className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
