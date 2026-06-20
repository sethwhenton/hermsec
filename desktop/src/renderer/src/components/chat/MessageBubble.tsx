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
  const reportLinks = message.reportLinks ?? (message.reportLink ? [message.reportLink] : []);

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
        <FormattedMessageContent content={message.content} rich />
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
        {reportLinks.length > 0 ? (
          <div className="mt-3 flex flex-col items-start gap-1.5">
            {reportLinks.map((link) => (
              <button
                key={`${link.label}-${link.path}`}
                type="button"
                className="inline-flex max-w-full items-center gap-1.5 rounded-md px-0.5 py-1 text-xs text-muted-foreground underline decoration-border underline-offset-4 transition-colors hover:text-foreground hover:decoration-foreground/70"
                title={link.path}
                onClick={() => {
                  void api?.scan.openReportLocation({ path: link.path });
                }}
              >
                <FolderOpen className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{link.label}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </motion.div>
  );
}

function FormattedMessageContent({
  content,
  rich,
}: {
  content: string;
  rich: boolean;
}) {
  const parts = rich ? parseRichBlocks(content) : parsePlainBlocks(content);

  return (
    <div className="space-y-3 break-words">
      {parts.map((part, index) => (
        <RichBlockView key={`${part.kind}-${index}`} block={part} />
      ))}
    </div>
  );
}

type RichBlock =
  | { kind: "paragraph"; text: string }
  | { kind: "heading"; level: 1 | 2 | 3; text: string }
  | { kind: "code"; text: string; language?: string }
  | { kind: "list"; ordered: boolean; items: Array<{ text: string; checked?: boolean }> }
  | { kind: "blockquote"; text: string }
  | { kind: "table"; headers: string[]; rows: string[][] }
  | { kind: "rule" };

function RichBlockView({ block }: { block: RichBlock }) {
  switch (block.kind) {
    case "heading": {
      const HeadingTag = block.level === 1 ? "h3" : block.level === 2 ? "h4" : "h5";
      return (
        <HeadingTag className={cn("font-semibold text-foreground", block.level === 1 ? "text-base" : "text-sm")}>
          {renderInlineMarkdown(block.text)}
        </HeadingTag>
      );
    }
    case "code":
      return (
        <div className="overflow-hidden rounded-xl border border-border/70 bg-background/70 shadow-inner">
          {block.language ? (
            <div className="border-b border-border/60 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
              {block.language}
            </div>
          ) : null}
          <pre className="max-h-[360px] overflow-auto p-3 font-mono text-[11px] leading-relaxed text-foreground/90">
            <code>{block.text}</code>
          </pre>
        </div>
      );
    case "list": {
      const ListTag = block.ordered ? "ol" : "ul";
      return (
        <ListTag className={cn("space-y-1 pl-5", block.ordered ? "list-decimal" : "list-disc")}>
          {block.items.map((item, itemIndex) => (
            <li key={`${item.text}-${itemIndex}`} className="pl-0.5">
              {item.checked !== undefined ? (
                <span className="mr-2 inline-flex h-3.5 w-3.5 translate-y-0.5 items-center justify-center rounded-sm border border-border/80 bg-background/70 text-[9px] text-foreground">
                  {item.checked ? <Check className="h-2.5 w-2.5" /> : null}
                </span>
              ) : null}
              {renderInlineMarkdown(item.text)}
            </li>
          ))}
        </ListTag>
      );
    }
    case "blockquote":
      return (
        <blockquote className="border-l-2 border-border pl-3 text-muted">
          {block.text.split(/\r?\n/).map((line, index) => (
            <Fragment key={`${line}-${index}`}>
              {index > 0 ? <br /> : null}
              {renderInlineMarkdown(line)}
            </Fragment>
          ))}
        </blockquote>
      );
    case "table":
      return (
        <div className="max-w-full overflow-x-auto rounded-xl border border-border/70">
          <table className="min-w-full border-collapse text-left text-xs">
            <thead className="bg-background/60 text-muted">
              <tr>
                {block.headers.map((header, index) => (
                  <th key={`${header}-${index}`} className="border-b border-border/70 px-3 py-2 font-medium">
                    {renderInlineMarkdown(header)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, rowIndex) => (
                <tr key={`row-${rowIndex}`} className="border-t border-border/50 first:border-t-0">
                  {block.headers.map((_, cellIndex) => (
                    <td key={`${rowIndex}-${cellIndex}`} className="px-3 py-2 align-top text-foreground/90">
                      {renderInlineMarkdown(row[cellIndex] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "rule":
      return <div className="h-px bg-border/70" />;
    case "paragraph":
    default:
      return (
        <p className="whitespace-pre-wrap">
          {renderInlineMarkdown(block.text)}
        </p>
      );
  }
}

function parsePlainBlocks(content: string): RichBlock[] {
  const text = content.trim();
  return text ? [{ kind: "paragraph", text }] : [];
}

function parseRichBlocks(content: string): RichBlock[] {
  const blocks: RichBlock[] = [];
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let index = 0;

  const pushParagraph = (paragraphLines: string[]) => {
    const text = paragraphLines.join("\n").trim();
    if (text) blocks.push({ kind: "paragraph", text });
  };

  while (index < lines.length) {
    const line = lines[index];

    if (!line.trim()) {
      index += 1;
      continue;
    }

    const fence = line.match(/^```([a-zA-Z0-9_+.-]+)?\s*$/);
    if (fence) {
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({
        kind: "code",
        text: trimTrailingBlankLines(codeLines).join("\n"),
        language: fence[1],
      });
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      blocks.push({
        kind: "heading",
        level: heading[1].length as 1 | 2 | 3,
        text: heading[2].trim(),
      });
      index += 1;
      continue;
    }

    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      index += 1;
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      const quoteLines: string[] = [];
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
        quoteLines.push(lines[index].replace(/^\s*>\s?/, ""));
        index += 1;
      }
      blocks.push({ kind: "blockquote", text: quoteLines.join("\n").trim() });
      continue;
    }

    if (isTableStart(lines, index)) {
      const { block, nextIndex } = parseTable(lines, index);
      blocks.push(block);
      index = nextIndex;
      continue;
    }

    const listMatch = parseListMarker(line);
    if (listMatch) {
      const ordered = listMatch.ordered;
      const items: Array<{ text: string; checked?: boolean }> = [];
      while (index < lines.length) {
        const item = parseListMarker(lines[index]);
        if (!item || item.ordered !== ordered) break;
        items.push({ text: item.text, checked: item.checked });
        index += 1;
      }
      blocks.push({ kind: "list", ordered, items });
      continue;
    }

    const paragraphLines = [line];
    index += 1;
    while (
      index < lines.length &&
      lines[index].trim() &&
      !lines[index].match(/^```/) &&
      !lines[index].match(/^(#{1,3})\s+/) &&
      !lines[index].match(/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/) &&
      !lines[index].match(/^\s*>\s?/) &&
      !isTableStart(lines, index) &&
      !parseListMarker(lines[index])
    ) {
      paragraphLines.push(lines[index]);
      index += 1;
    }
    pushParagraph(paragraphLines);
  }

  return blocks;
}

function renderInlineMarkdown(text: string, depth = 0): ReactNode[] {
  if (!text) return [];
  if (depth > 3) return [text];

  const nodes: ReactNode[] = [];
  const tokenPattern =
    /(`[^`\n]+`|\[[^\]\n]+\]\((?:<[^>\n]+>|[^)\n]+)\)|https?:\/\/[^\s<>()]+|~~[^~\n][\s\S]*?[^~\n]~~|\*\*[^*\n][\s\S]*?[^*\n]\*\*|__[^_\n][\s\S]*?[^_\n]__|\*[^*\s][^*\n]*\*|_[^_\s][^_\n]*_)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = tokenPattern.exec(text))) {
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
    } else if (token.startsWith("[") && token.includes("](")) {
      const parsed = parseMarkdownLink(token);
      nodes.push(
        parsed ? (
          <RichLink key={`link-${match.index}`} label={parsed.label} target={parsed.target} />
        ) : (
          token
        ),
      );
    } else if (token.startsWith("http://") || token.startsWith("https://")) {
      nodes.push(<RichLink key={`url-${match.index}`} label={token} target={token} />);
    } else if (token.startsWith("~~")) {
      nodes.push(
        <del key={`del-${match.index}`} className="text-muted-foreground">
          {renderInlineMarkdown(token.slice(2, -2), depth + 1)}
        </del>,
      );
    } else if (token.startsWith("**") || token.startsWith("__")) {
      nodes.push(
        <strong key={`strong-${match.index}`} className="font-semibold text-foreground">
          {renderInlineMarkdown(token.slice(2, -2), depth + 1)}
        </strong>,
      );
    } else {
      nodes.push(
        <em key={`em-${match.index}`} className="text-foreground/95">
          {renderInlineMarkdown(token.slice(1, -1), depth + 1)}
        </em>,
      );
    }

    lastIndex = tokenPattern.lastIndex;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes.map((node, index) => <Fragment key={index}>{node}</Fragment>);
}

function RichLink({ label, target }: { label: string; target: string }) {
  const safeTarget = safeRichLinkTarget(target);

  if (!safeTarget) {
    return <span>{label}</span>;
  }

  return (
    <button
      type="button"
      className="inline break-all text-accent underline decoration-accent/40 underline-offset-4 transition-colors duration-150 ease-out hover:decoration-accent active:scale-[0.97]"
      title={safeTarget}
      onClick={() => {
        window.open(safeTarget, "_blank", "noopener,noreferrer");
      }}
    >
      {label}
    </button>
  );
}

function parseMarkdownLink(token: string): { label: string; target: string } | null {
  const match = token.match(/^\[([^\]\n]+)\]\((<[^>\n]+>|[^)\n]+)\)$/);
  if (!match) return null;
  return {
    label: match[1],
    target: match[2].replace(/^<|>$/g, "").trim(),
  };
}

function safeRichLinkTarget(target: string): string | null {
  const value = target.trim();
  if (!value || /[\u0000-\u001f]/.test(value)) return null;
  try {
    const url = new URL(value);
    return ["http:", "https:", "mailto:"].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function parseListMarker(line: string): { ordered: boolean; text: string; checked?: boolean } | null {
  const unordered = line.match(/^\s*[-*+]\s+(?:\[([ xX])\]\s+)?(.+)$/);
  if (unordered) {
    return {
      ordered: false,
      checked: unordered[1] ? unordered[1].toLowerCase() === "x" : undefined,
      text: unordered[2].trim(),
    };
  }

  const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
  return ordered ? { ordered: true, text: ordered[1].trim() } : null;
}

function isTableStart(lines: string[], index: number): boolean {
  const header = lines[index];
  const separator = lines[index + 1];
  return Boolean(
    header?.includes("|") &&
      separator &&
      /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(separator),
  );
}

function parseTable(lines: string[], index: number): { block: Extract<RichBlock, { kind: "table" }>; nextIndex: number } {
  const headers = splitTableCells(lines[index]);
  const rows: string[][] = [];
  index += 2;

  while (index < lines.length && lines[index].includes("|") && lines[index].trim()) {
    rows.push(splitTableCells(lines[index]));
    index += 1;
  }

  return { block: { kind: "table", headers, rows }, nextIndex: index };
}

function splitTableCells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function trimTrailingBlankLines(lines: string[]): string[] {
  const next = [...lines];
  while (next.length > 0 && !next[next.length - 1].trim()) {
    next.pop();
  }
  return next;
}
