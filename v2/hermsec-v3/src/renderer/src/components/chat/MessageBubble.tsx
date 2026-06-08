import { motion } from "framer-motion";
import { Check, Copy, FolderOpen } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { getHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import type { ChatMessage } from "@/types/chat";

interface MessageBubbleProps {
  message: ChatMessage;
}

export function MessageBubble({ message }: MessageBubbleProps) {
  const isUser = message.role === "user";
  const api = getHermsecApi();
  const [copied, setCopied] = useState(false);

  const copyPrompt = async () => {
    if (!message.copyAction?.text) return;
    try {
      await navigator.clipboard.writeText(message.copyAction.text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  };

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
        <FormattedMessageContent content={message.content} />
        {!isUser && message.copyAction ? (
          <div className="mt-3 flex items-center gap-2 border-t border-border/60 pt-2">
            <button
              type="button"
              className="inline-flex items-center gap-1.5 rounded-md px-1.5 py-1 text-[11px] text-muted-foreground transition-colors duration-150 ease-out hover:bg-surface-hover hover:text-foreground active:scale-[0.97]"
              onClick={copyPrompt}
              title={message.copyAction.label}
            >
              {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? "Copied" : message.copyAction.label}</span>
            </button>
          </div>
        ) : null}
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

function FormattedMessageContent({ content }: { content: string }) {
  const parts = splitCodeFences(content);
  return (
    <div className="space-y-3">
      {parts.map((part, index) =>
        part.kind === "code" ? (
          <pre
            key={`${part.kind}-${index}`}
            className="max-h-[360px] overflow-auto rounded-xl border border-border/70 bg-background/70 p-3 font-mono text-[11px] leading-relaxed text-foreground/90 shadow-inner"
          >
            <code>{part.text}</code>
          </pre>
        ) : part.text.trim() ? (
          <FormattedText key={`${part.kind}-${index}`} text={part.text} />
        ) : null,
      )}
    </div>
  );
}

function FormattedText({ text }: { text: string }) {
  const blocks = splitTextBlocks(text);
  return (
    <>
      {blocks.map((block, index) => {
        if (block.kind === "list") {
          return (
            <ul key={`${block.kind}-${index}`} className="list-disc space-y-1 pl-5">
              {block.items.map((item, itemIndex) => (
                <li key={`${block.kind}-${index}-${itemIndex}`} className="whitespace-pre-wrap">
                  {renderInlineMarkdown(item)}
                </li>
              ))}
            </ul>
          );
        }

        return (
          <p key={`${block.kind}-${index}`} className="whitespace-pre-wrap">
            {renderInlineMarkdown(block.text)}
          </p>
        );
      })}
    </>
  );
}

type TextBlock =
  | { kind: "paragraph"; text: string }
  | { kind: "list"; items: string[] };

function splitTextBlocks(text: string): TextBlock[] {
  const blocks: TextBlock[] = [];
  let paragraph: string[] = [];
  let list: string[] = [];

  const flushParagraph = () => {
    if (!paragraph.length) return;
    blocks.push({ kind: "paragraph", text: paragraph.join("\n") });
    paragraph = [];
  };

  const flushList = () => {
    if (!list.length) return;
    blocks.push({ kind: "list", items: list });
    list = [];
  };

  for (const line of text.split(/\r?\n/)) {
    const listMatch = line.match(/^\s*[-*]\s+(.+)$/);
    if (listMatch) {
      flushParagraph();
      list.push(listMatch[1]);
      continue;
    }

    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }

    flushList();
    paragraph.push(line);
  }

  flushParagraph();
  flushList();
  return blocks;
}

function renderInlineMarkdown(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern = /(`[^`\n]+`|\*\*[^*\n][\s\S]*?[^*\n]\*\*|__[^_\n][\s\S]*?[^_\n]__)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text))) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }

    const token = match[0];
    if (token.startsWith("`")) {
      nodes.push(
        <code
          key={`code-${match.index}`}
          className="rounded-md border border-border/70 bg-background/70 px-1.5 py-0.5 font-mono text-[0.85em] text-foreground"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      nodes.push(
        <strong key={`strong-${match.index}`} className="font-semibold text-foreground">
          {token.slice(2, -2)}
        </strong>,
      );
    }

    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes.map((node, index) => <Fragment key={index}>{node}</Fragment>);
}

function splitCodeFences(content: string): Array<{ kind: "text" | "code"; text: string }> {
  const parts: Array<{ kind: "text" | "code"; text: string }> = [];
  const pattern = /```(?:[a-zA-Z0-9_-]+)?\r?\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(content))) {
    if (match.index > lastIndex) {
      parts.push({ kind: "text", text: content.slice(lastIndex, match.index).trimEnd() });
    }
    parts.push({ kind: "code", text: match[1].trim() });
    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < content.length) {
    parts.push({ kind: "text", text: content.slice(lastIndex).trimStart() });
  }

  return parts.length ? parts : [{ kind: "text", text: content }];
}
