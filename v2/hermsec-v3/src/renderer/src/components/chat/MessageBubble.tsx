import { motion } from "framer-motion";
import { FolderOpen } from "lucide-react";
import { getHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import type { ChatMessage } from "@/types/chat";

interface MessageBubbleProps {
  message: ChatMessage;
}

export function MessageBubble({ message }: MessageBubbleProps) {
  const isUser = message.role === "user";
  const api = getHermsecApi();

  return (
    <motion.div
      className={cn("flex w-full", isUser ? "justify-end" : "justify-start")}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
    >
      <div
        className={cn(
          "rounded-[22px] px-4 py-3 text-sm leading-relaxed shadow-[0_16px_50px_rgba(0,0,0,0.2)]",
          isUser
            ? "max-w-[78%] border border-border/70 bg-surface-elevated text-foreground sm:max-w-[68%]"
            : "max-w-[min(680px,92%)] border border-border/80 bg-surface-elevated/78 text-foreground backdrop-blur",
        )}
      >
        <p className="whitespace-pre-wrap">{message.content}</p>
        {message.reportLink ? (
          <button
            type="button"
            className="mt-3 inline-flex max-w-full items-center gap-1.5 rounded-md border border-border bg-background/60 px-2.5 py-1.5 text-xs text-accent transition-colors hover:border-accent/40 hover:bg-accent-muted hover:text-foreground"
            onClick={() => {
              void api?.scan.openReportLocation({ path: message.reportLink?.path ?? "" });
            }}
          >
            <FolderOpen className="h-3.5 w-3.5 shrink-0" />
            <span className="truncate">{message.reportLink.label}</span>
          </button>
        ) : null}
      </div>
    </motion.div>
  );
}
