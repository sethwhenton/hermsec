import { useEffect, useRef } from "react";
import { useUiStore } from "@/store/uiStore";
import { AgentQuestions } from "./AgentQuestions";
import { MessageBubble } from "./MessageBubble";
import { ThinkingRow } from "./ThinkingRow";

interface MessageListProps {
  onQuestionsSubmit?: (answers: Record<string, string[]>) => void;
}

export function MessageList({ onQuestionsSubmit }: MessageListProps) {
  const chatItems = useUiStore((s) => s.chatItems);
  const isAgentThinking = useUiStore((s) => s.isAgentThinking);
  const updateChatItem = useUiStore((s) => s.updateChatItem);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatItems, isAgentThinking]);

  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-4 py-6 sm:px-6">
      <div className="mx-auto flex w-full max-w-[760px] flex-col gap-4">
        {chatItems.map((item) => {
          if (item.kind === "message") {
            return <MessageBubble key={item.id} message={item.message} />;
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
        <ThinkingRow visible={isAgentThinking} />
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
