import { HermsecLogo } from "~/components/HermsecLogo";
import { COMPOSER_MAX_WIDTH_CLASS_NAME } from "~/components/chat/composerPickerStyles";
import { cn } from "~/lib/utils";
import { HermsecChatInput } from "./HermsecChatInput";
import { HermsecQuickActionBar } from "./HermsecQuickActionBar";
import type { HermsecChatChoice, HermsecChatMessage } from "../types";

type HermsecChatSurfaceProps = {
  messages: HermsecChatMessage[];
  projectName?: string;
  onQuickAction?: (actionId: string) => void;
  onSendMessage?: (message: string) => void;
  onChoice?: (choice: HermsecChatChoice) => void;
};

export function HermsecChatSurface({
  messages,
  projectName,
  onQuickAction,
  onSendMessage,
  onChoice,
}: HermsecChatSurfaceProps) {
  const isEmpty = messages.length === 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        {isEmpty ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-5 px-6 pb-8 select-none">
            <HermsecLogo aria-label="Hermsec V2 logo" className="size-10 text-foreground/85" />
            <div className="flex flex-col items-center gap-1">
              <h1 className="text-xl font-semibold text-foreground/90">
                What should Hermsec investigate?
              </h1>
              {projectName ? (
                <span className="text-sm text-muted-foreground/45">{projectName}</span>
              ) : null}
            </div>
            <HermsecQuickActionBar onAction={onQuickAction} />
          </div>
        ) : (
          <div className={cn("mx-auto w-full space-y-4 px-4 py-6", COMPOSER_MAX_WIDTH_CLASS_NAME)}>
            {messages.map((message) => (
              <div
                key={message.id}
                className={cn(
                  "rounded-lg border px-3 py-2.5 text-[length:var(--app-font-size-ui,12px)] leading-relaxed",
                  message.role === "user"
                    ? "ml-8 border-[color:var(--color-border)] bg-white/[0.02] text-foreground/90"
                    : "mr-8 border-transparent bg-transparent text-foreground/80",
                )}
              >
                <div className="whitespace-pre-wrap">{message.content}</div>
                {message.choices?.length ? (
                  <div className="mt-3 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-white/[0.025]">
                    {message.choices.map((choice, index) => (
                      <button
                        key={choice.id}
                        type="button"
                        onClick={() => onChoice?.(choice)}
                        className={cn(
                          "grid w-full grid-cols-[1.5rem_minmax(0,1fr)] gap-2 px-3 py-2 text-left",
                          "transition-colors hover:bg-white/[0.055] focus-visible:bg-white/[0.055]",
                          index > 0 && "border-t border-[color:var(--color-border)]",
                        )}
                      >
                        <span className="text-[11px] text-muted-foreground/55">{index + 1}.</span>
                        <span className="min-w-0">
                          <span className="block text-[12px] font-medium text-foreground/88">
                            {choice.label}
                          </span>
                          <span className="block text-[11px] text-muted-foreground/62">
                            {choice.description}
                          </span>
                        </span>
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
      <HermsecChatInput onSubmit={onSendMessage} />
    </div>
  );
}
