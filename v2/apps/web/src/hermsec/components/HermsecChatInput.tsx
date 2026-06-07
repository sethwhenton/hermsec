import { useState } from "react";
import { ArrowUpIcon } from "~/lib/icons";
import { Button } from "~/components/ui/button";
import {
  COMPOSER_MAX_WIDTH_CLASS_NAME,
  COMPOSER_PICKER_RADIUS_CLASS_NAME,
  COMPOSER_SURFACE_SHADOW_CLASS_NAME,
} from "~/components/chat/composerPickerStyles";
import { cn } from "~/lib/utils";

type HermsecChatInputProps = {
  onSubmit?: (message: string) => void;
  placeholder?: string;
};

export function HermsecChatInput({
  onSubmit,
  placeholder = "Ask Hermsec to investigate, scan, or explain…",
}: HermsecChatInputProps) {
  const [value, setValue] = useState("");

  function handleSubmit() {
    const trimmed = value.trim();
    if (!trimmed) return;
    onSubmit?.(trimmed);
    setValue("");
  }

  return (
    <div className={cn("w-full px-4 pb-5", COMPOSER_MAX_WIDTH_CLASS_NAME, "mx-auto")}>
      <form
        className={cn(
          "flex items-end gap-2 border border-[color:var(--color-border)] bg-[color-mix(in_srgb,var(--background)_88%,#0b0b0b)] p-2.5",
          COMPOSER_PICKER_RADIUS_CLASS_NAME,
          COMPOSER_SURFACE_SHADOW_CLASS_NAME,
        )}
        onSubmit={(event) => {
          event.preventDefault();
          handleSubmit();
        }}
      >
        <textarea
          value={value}
          onChange={(event) => setValue(event.target.value)}
          rows={1}
          placeholder={placeholder}
          className={cn(
            "max-h-32 min-h-[2.25rem] flex-1 resize-none bg-transparent px-1 py-1.5",
            "text-[length:var(--app-font-size-ui,12px)] leading-relaxed text-foreground/90",
            "placeholder:text-muted-foreground/45 outline-none",
          )}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              handleSubmit();
            }
          }}
        />
        <Button
          type="submit"
          size="icon-sm"
          variant="default"
          disabled={!value.trim()}
          className="shrink-0 rounded-md"
          aria-label="Send message"
        >
          <ArrowUpIcon className="size-3.5" />
        </Button>
      </form>
    </div>
  );
}
