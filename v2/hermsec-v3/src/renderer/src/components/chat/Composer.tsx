import { ArrowUp, RotateCw, Square } from "lucide-react";
import { useRef, useState, type KeyboardEvent } from "react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/Button";
import { ContextBar } from "./ContextBar";

interface ComposerProps {
  onSend: (text: string) => void;
  disabled?: boolean;
  scanRunning?: boolean;
  onStopScan?: () => void;
  onRestartScan?: () => void;
  className?: string;
  compact?: boolean;
}

export function Composer({
  onSend,
  disabled,
  scanRunning,
  onStopScan,
  onRestartScan,
  className,
  compact,
}: ComposerProps) {
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
        "border border-border/80 bg-surface-elevated/95 shadow-[0_22px_80px_rgba(0,0,0,0.42)] backdrop-blur",
        compact ? "rounded-[20px] px-3 py-2.5" : "rounded-[28px] p-4",
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
        placeholder={compact ? "Ask for follow-up changes" : "Need to scan your project? Just ask!"}
        rows={1}
        className={cn(
          "no-drag w-full resize-none bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none",
          compact ? "mb-2 min-h-7" : "mb-3",
        )}
      />
      {compact ? (
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {scanRunning ? (
              <>
                <Button variant="outline" size="icon" title="Stop scan" onClick={onStopScan}>
                  <Square className="h-3.5 w-3.5 fill-current" />
                </Button>
                <Button variant="ghost" size="icon" title="Restart scan" onClick={onRestartScan}>
                  <RotateCw className="h-3.5 w-3.5" />
                </Button>
              </>
            ) : null}
            <ContextBar />
          </div>
          <Button
            size="icon"
            className="shrink-0 rounded-full"
            disabled={!value.trim() || disabled}
            onClick={handleSend}
          >
            <ArrowUp className="h-4 w-4" />
          </Button>
        </div>
      ) : (
        <>
          <div className="mb-3">
            <ContextBar />
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              {scanRunning ? (
                <>
                  <Button variant="outline" size="icon" title="Stop scan" onClick={onStopScan}>
                    <Square className="h-3.5 w-3.5 fill-current" />
                  </Button>
                  <Button variant="ghost" size="icon" title="Restart scan" onClick={onRestartScan}>
                    <RotateCw className="h-3.5 w-3.5" />
                  </Button>
                </>
              ) : null}
            </div>
            <Button
              size="icon"
              className="rounded-full"
              disabled={!value.trim() || disabled}
              onClick={handleSend}
            >
              <ArrowUp className="h-4 w-4" />
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
