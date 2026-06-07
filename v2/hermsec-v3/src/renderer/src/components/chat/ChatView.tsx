import { AnimatePresence, motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { requireHermsecApi } from "@/lib/ipc";
import { useReportStore } from "@/store/reportStore";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import type { ChatItem, ChatMessage } from "@/types/chat";
import { ScanProgressPanel } from "@/components/scan/ScanProgressPanel";
import { Composer } from "./Composer";
import { MessageList } from "./MessageList";
import { QuickActions } from "./QuickActions";

function createId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function ChatView() {
  const chatItems = useUiStore((s) => s.chatItems);
  const isAgentThinking = useUiStore((s) => s.isAgentThinking);
  const setChatItems = useUiStore((s) => s.setChatItems);
  const setAgentThinking = useUiStore((s) => s.setAgentThinking);
  const persistCurrentSession = useSessionStore((s) => s.persistCurrentSession);
  const settings = useSettingsStore((s) => s.settings);
  const setView = useUiStore((s) => s.setView);
  const runScan = useReportStore((s) => s.runScan);
  const progress = useReportStore((s) => s.progress);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const latestReport = useReportStore((s) => s.latestReport);

  const hasMessages = chatItems.length > 0;

  const pushMessage = async (
    role: ChatMessage["role"],
    content: string,
    reportLink?: ChatMessage["reportLink"],
  ) => {
    const item: ChatItem = {
      kind: "message",
      id: createId(),
      message: { id: createId(), role, content, createdAt: Date.now(), ...(reportLink ? { reportLink } : {}) },
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);
    await persistCurrentSession(
      settings?.defaultProjectDir ?? "",
      nextItems,
      role === "user" ? content : undefined,
    );
  };

  const pushQuestions = async () => {
    const item: ChatItem = {
      kind: "questions",
      id: createId(),
      questions: [
        {
          id: "hermsec_action",
          prompt: "Choose what you want Hermsec to do next.",
          options: [
            { id: "scan_repo", label: "Scan repo" },
            { id: "set_automation", label: "Set an automation" },
          ],
        },
      ],
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);
    await persistCurrentSession(settings?.defaultProjectDir ?? "", nextItems);
  };

  const isScanRequest = (text: string) => {
    const lower = text.toLowerCase();
    if (/^(what|which|why|how|explain|summarize|show me|tell me)\b/.test(lower)) {
      return false;
    }
    return /\b(scan|rescan)\b/.test(lower) || /\b(run|start|perform)\s+(a\s+)?scan\b/.test(lower);
  };

  const runProjectScan = async () => {
    const result = await runScan({
      targetPath: settings?.defaultProjectDir,
      reportDir: settings?.defaultReportDir,
      mode: "online",
      useModel: true,
    });

    if (!result.ok) {
      await pushMessage("assistant", `Scan failed. ${result.message}`);
      return;
    }

    const savedPath = result.reportDir ?? result.htmlPath;
    await pushMessage(
      "assistant",
      savedPath
        ? `Scan completed. The report has been saved in your specified file directory:\n${savedPath}`
        : "Scan completed. The report has been saved in your specified file directory.",
      savedPath
        ? {
            label: "Open report folder in File Explorer",
            path: savedPath,
          }
        : undefined,
    );
  };

  const handleSend = async (text: string) => {
    await pushMessage("user", text);
    setAgentThinking(true);

    try {
      const currentItems = useUiStore.getState().chatItems;
      const latestReportPath = latestReport?.htmlPath ?? findLatestReportPath(currentItems);
      if (isScanRequest(text)) {
        await runProjectScan();
        return;
      }

      if (wantsCapabilities(text.toLowerCase())) {
        await pushMessage(
          "assistant",
          "I can help with Hermsec security work for this project. The two core MVP actions are scanning the selected repo and setting an in-app automation that reruns scans when the project changes.",
        );
        await pushQuestions();
        return;
      }

      const response = await answerSecurityQuestion(text, latestReportPath);
      await pushMessage("assistant", response);
    } catch (error) {
      await pushMessage(
        "assistant",
        error instanceof Error ? `Hermsec could not complete that action. ${error.message}` : "Hermsec could not complete that action.",
      );
    } finally {
      setAgentThinking(false);
    }
  };

  const handleQuickAction = (action: string) => {
    void handleSend(`Run ${action.toLowerCase()} for the current project`);
  };

  const handleQuestionSubmit = (answers: Record<string, string[]>) => {
    const action = answers.hermsec_action?.[0];
    if (action === "scan_repo") {
      void handleSend("Scan project");
      return;
    }
    if (action === "set_automation") {
      void pushMessage(
        "assistant",
        "Use the clock button in the top-right action strip to configure the in-app automation frequency and exact run time.",
      );
      setView("chat");
    }
  };

  return (
    <div className="relative flex h-full min-h-0 flex-col overflow-hidden">
      <AnimatePresence>
        {hasMessages && (
          <motion.div
            key="messages"
            className="min-h-0 flex-1"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <MessageList onQuestionsSubmit={handleQuestionSubmit} />
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {scanRunning && (
          <motion.div
            className="pointer-events-none absolute right-6 top-6 z-20 w-[380px] max-w-[calc(100%-3rem)]"
            initial={{ opacity: 0, y: -8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.18 }}
          >
            <div className="pointer-events-auto">
              <ScanProgressPanel events={progress} compact />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <motion.div
        layout
        transition={{ type: "spring", stiffness: 420, damping: 38 }}
        className={cn(
          "mx-auto w-full max-w-3xl shrink-0 px-6",
          hasMessages ? "pb-6 pt-2" : "flex flex-1 flex-col items-center justify-center gap-5 pb-12",
        )}
      >
        <AnimatePresence mode="wait">
          {!hasMessages && (
            <motion.div
              key="empty-prompt"
              className="flex w-full flex-col items-center gap-5"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22 }}
            >
              <h1 className="text-center text-[1.65rem] font-medium tracking-tight text-foreground">
                What should we work on?
              </h1>
              <QuickActions onAction={handleQuickAction} />
            </motion.div>
          )}
        </AnimatePresence>

        <motion.div layout className="w-full">
          <Composer onSend={handleSend} disabled={isAgentThinking} />
        </motion.div>
      </motion.div>
    </div>
  );
}

function findLatestReportPath(chatItems: ChatItem[]): string | undefined {
  for (const item of [...chatItems].reverse()) {
    if (item.kind === "message" && item.message.reportLink?.path.endsWith("report.html")) {
      return item.message.reportLink.path;
    }
  }
  return undefined;
}

async function answerSecurityQuestion(text: string, latestReportPath?: string): Promise<string> {
  const lower = text.toLowerCase();

  if (wantsCapabilities(lower)) {
    return [
      "I can help with Hermsec security work for this project:",
      "1. Scan the selected repo in Offline, Auto, or Online mode.",
      "2. Explain the latest HTML report and summarize the real findings.",
      "3. Prioritize fixes by severity, secrets exposure, and exploitability.",
      "4. Talk through remediation steps and what to rerun after patching.",
      "5. Help configure report folders, model/provider settings, and project sessions.",
      "",
      "Ask me to scan the project, explain the latest report, list the highest-risk findings, or suggest what to fix first.",
    ].join("\n");
  }

  if (wantsReportExplanation(lower)) {
    if (!latestReportPath) {
      return "I do not have a report in this chat yet. Run `Scan project` first, then ask me to explain the HTML report, summarize findings, or prioritize fixes.";
    }

    const result = await requireHermsecApi().reports.explain({
      reportPath: latestReportPath,
      question: text,
    });
    return result.ok
      ? result.message
      : `I found the latest report reference, but could not explain it yet. ${result.message}`;
  }

  if (/\b(automation|schedule|cron|daily|weekly|background)\b/.test(lower)) {
    return "For automations, Hermsec should run scheduled security scans for a selected project, write the HTML/JSON report to your configured report directory, and preserve the result in the project session history. The next useful step is choosing the project, schedule, scan mode, and report destination.";
  }

  if (/\b(doctor|health|check setup|scanner|tooling|semgrep|gitleaks|bandit|osv|pmg)\b/.test(lower)) {
    return "Doctor mode is for checking whether Hermsec can actually run its security stack: local scanners, package audit tools, report output paths, model/provider config, and environment access. If a scan looks incomplete, Doctor is the first thing to run.";
  }

  if (/\b(online|offline|auto mode|scan mode|mode)\b/.test(lower)) {
    return "Hermsec has three scan modes. Offline uses local deterministic checks and available local scanners. Auto chooses a practical default based on environment. Online runs the fuller vulnerability-intelligence path and is the mode to use when you want the strongest repo security pass.";
  }

  if (isSecurityScoped(lower)) {
    if (latestReportPath) {
      const result = await requireHermsecApi().reports.explain({
        reportPath: latestReportPath,
        question: text,
      });
      if (result.ok) return result.message;
    }
    return "I can help with that security question, but I need scan evidence for a precise answer. Run `Scan project` first, then I can explain findings, severity, likely impact, and remediation from the generated report.";
  }

  return "I’m scoped to Hermsec security work: repository scans, vulnerability findings, report explanations, remediation, scanner setup, and security automations. Ask me something about this project’s security posture or run a scan to give me evidence to work from.";
}

function wantsCapabilities(text: string): boolean {
  return /\b(what can you do|help|capabilities|commands|how do you work)\b/.test(text);
}

function wantsReportExplanation(text: string): boolean {
  return /\b(report|html|scan|found|finding|findings|summary|explain|severity|critical|high|medium|secret|token|fix|remediate|priority|prioritize)\b/.test(text);
}

function isSecurityScoped(text: string): boolean {
  return /\b(security|vulnerab|cve|cwe|secret|token|credential|injection|xss|sql|command|eval|dependency|supply chain|npm|package|risk|threat|exploit|patch|remediate|repo|project)\b/.test(text);
}
