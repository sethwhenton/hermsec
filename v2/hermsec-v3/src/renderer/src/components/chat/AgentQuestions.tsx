import { motion } from "framer-motion";
import { useState } from "react";
import { cn } from "@/lib/cn";
import type { AgentQuestion } from "@/types/chat";
import { Button } from "@/components/ui/Button";

interface AgentQuestionsProps {
  questions: AgentQuestion[];
  submitted?: boolean;
  answers?: Record<string, string[]>;
  onSubmit: (answers: Record<string, string[]>) => void;
  disabled?: boolean;
}

export function AgentQuestions({
  questions,
  submitted = false,
  answers: initialAnswers,
  onSubmit,
  disabled,
}: AgentQuestionsProps) {
  const [selections, setSelections] = useState<Record<string, string[]>>(initialAnswers ?? {});

  const toggleOption = (question: AgentQuestion, optionId: string) => {
    if (submitted || disabled) return;
    setSelections((prev) => {
      const current = prev[question.id] ?? [];
      if (question.allowMultiple) {
        const next = current.includes(optionId)
          ? current.filter((id) => id !== optionId)
          : [...current, optionId];
        return { ...prev, [question.id]: next };
      }
      return { ...prev, [question.id]: [optionId] };
    });
  };

  const handleSubmit = () => {
    onSubmit(selections);
  };

  const allAnswered = questions.every((q) => (selections[q.id]?.length ?? 0) > 0);

  return (
    <motion.div
      className="w-full max-w-[680px] rounded-[20px] border border-border/80 bg-surface-elevated/85 p-4 shadow-[0_16px_50px_rgba(0,0,0,0.22)]"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 380, damping: 32 }}
    >
      <div className="mb-3 text-xs font-medium text-muted">Agent needs your input</div>
      <div className="space-y-4">
        {questions.map((question) => (
          <div key={question.id}>
            <p className="mb-2 text-sm text-foreground">{question.prompt}</p>
            <div className="space-y-1">
              {question.options.map((option) => {
                const selected = selections[question.id]?.includes(option.id) ?? false;
                return (
                  <button
                    key={option.id}
                    type="button"
                    disabled={submitted || disabled}
                    onClick={() => toggleOption(question, option.id)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md border px-3 py-2 text-left text-sm transition-colors",
                      selected
                        ? "border-accent/50 bg-accent-muted text-foreground"
                        : "border-border bg-surface text-muted hover:border-foreground/20 hover:text-foreground",
                      (submitted || disabled) && "pointer-events-none opacity-70",
                    )}
                  >
                    <span
                      className={cn(
                        "flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                        selected ? "border-accent bg-accent text-background" : "border-border",
                      )}
                    >
                      {selected && <span className="text-[10px]">✓</span>}
                    </span>
                    {option.label}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between">
        {submitted ? (
          <span className="text-xs text-success">Responses submitted</span>
        ) : (
          <Button size="sm" disabled={!allAnswered || disabled} onClick={handleSubmit}>
            Submit answers
          </Button>
        )}
      </div>
    </motion.div>
  );
}
