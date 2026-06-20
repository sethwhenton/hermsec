import { useEffect, useRef, useState } from "react";
import { ArrowDown } from "lucide-react";
import { ScanProgressDisclosure } from "@/components/scan/ScanProgressPanel";
import { useReportStore } from "@/store/reportStore";
import { useUiStore } from "@/store/uiStore";
import { AgentQuestions } from "./AgentQuestions";
import { DoctorCard } from "./DoctorCard";
import { MessageBubble } from "./MessageBubble";
import { ThinkingRow } from "./ThinkingRow";

interface MessageListProps {
  onQuestionsSubmit?: (answers: Record<string, string[]>) => void;
}

export function MessageList({ onQuestionsSubmit }: MessageListProps) {
  const chatItems = useUiStore((s) => s.chatItems);
  const isAgentThinking = useUiStore((s) => s.isAgentThinking);
  const agentStatus = useUiStore((s) => s.agentStatus);
  const updateChatItem = useUiStore((s) => s.updateChatItem);
  const progress = useReportStore((s) => s.progress);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const nearBottomRef = useRef(true);
  const suppressJumpUntilRef = useRef(0);
  const [showJumpToLatest, setShowJumpToLatest] = useState(false);

  useEffect(() => {
    if (nearBottomRef.current) {
      suppressJumpUntilRef.current = Date.now() + 350;
      setShowJumpToLatest(false);
      const frame = window.requestAnimationFrame(() => {
        bottomRef.current?.scrollIntoView({ behavior: "auto", block: "end" });
      });
      return () => window.cancelAnimationFrame(frame);
    }
    return undefined;
  }, [chatItems, isAgentThinking, progress.length, scanRunning]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    if (Date.now() < suppressJumpUntilRef.current) {
      nearBottomRef.current = true;
      setShowJumpToLatest(false);
      return;
    }
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
    nearBottomRef.current = nearBottom;
    setShowJumpToLatest(!nearBottom);
  };

  const scrollToLatest = () => {
    nearBottomRef.current = true;
    setShowJumpToLatest(false);
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  };

  return (
    <div className="relative h-full min-h-0">
      <div
        ref={scrollRef}
        className="h-full min-h-0 overflow-y-auto px-4 pb-16 pt-20 sm:px-6 sm:pt-24"
        onScroll={handleScroll}
      >
        <div className="mx-auto flex w-full max-w-[760px] flex-col gap-5">
          {chatItems.map((item) => {
            if (item.kind === "message") {
              return <MessageBubble key={item.id} message={item.message} />;
            }
            if (item.kind === "doctor") {
              return (
                <DoctorCard
                  key={item.id}
                  result={item.result}
                  progress={item.progress}
                  running={item.running}
                  error={item.error}
                />
              );
            }
            if (item.kind === "scan-progress") {
              return (
                <ScanProgressDisclosure
                  key={item.id}
                  events={item.events}
                  running={item.running}
                  visible
                />
              );
            }
            return (
              <AgentQuestions
                key={item.id}
                questions={item.questions}
                submitted={item.submitted}
                answers={item.answers}
                onSubmit={(answers) => {
                  updateChatItem(item.id, (current) =>
                    current.kind === "questions"
                      ? { ...current, submitted: true, answers }
                      : current,
                  );
                  onQuestionsSubmit?.(answers);
                }}
              />
            );
          })}
          <ThinkingRow visible={isAgentThinking && !scanRunning} status={agentStatus} />
          <ScanProgressDisclosure
            events={progress}
            running={scanRunning}
            visible={scanRunning}
          />
          <div ref={bottomRef} />
        </div>
      </div>
      {showJumpToLatest ? (
        <button
          type="button"
          className="absolute bottom-4 left-1/2 z-20 inline-flex h-9 w-9 -translate-x-1/2 items-center justify-center rounded-full border border-border/70 bg-accent/85 text-white shadow-[0_14px_40px_rgba(37,99,235,0.36)] backdrop-blur transition-transform duration-150 ease-out hover:scale-105 hover:bg-accent active:scale-95"
          onClick={scrollToLatest}
          title="Jump to latest message"
        >
          <ArrowDown className="h-4 w-4" />
        </button>
      ) : null}
    </div>
  );
}
