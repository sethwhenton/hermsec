import { motion } from "framer-motion";
import { Check } from "lucide-react";
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
            <div className="space-y-1.5">
              {question.options.map((option) => {
                const selected = selections[question.id]?.includes(option.id) ?? false;
                return (
                  <button
                    key={option.id}
                    type="button"
                    disabled={submitted || disabled}
                    onClick={() => toggleOption(question, option.id)}
                    className={cn(
                      "group flex w-full items-start gap-2 rounded-lg border px-3 py-2.5 text-left text-sm transition-all duration-150 ease-out",
                      selected
                        ? "border-accent/55 bg-accent-muted text-foreground shadow-[0_0_0_1px_rgba(255,255,255,0.03)]"
                        : "border-border bg-surface text-muted hover:border-foreground/20 hover:bg-white/[0.03] hover:text-foreground",
                      (submitted || disabled) && "pointer-events-none opacity-70",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors",
                        selected ? "border-accent bg-accent text-background" : "border-border",
                      )}
                    >
                      {selected && <Check className="h-3 w-3" strokeWidth={3} />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block font-medium leading-5">{option.label}</span>
                      {option.description ? (
                        <span className="mt-0.5 block text-xs leading-4 text-muted">{option.description}</span>
                      ) : null}
                      {option.meta ? (
                        <span className="mt-1 inline-flex rounded-full border border-border-subtle bg-background px-2 py-0.5 text-[10px] font-medium text-muted">
                          {option.meta}
                        </span>
                      ) : null}
                    </span>
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
