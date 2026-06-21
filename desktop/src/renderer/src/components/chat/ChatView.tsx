import { AnimatePresence, motion } from "framer-motion";
import { Clock, LayoutDashboard } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { requireHermsecApi } from "@/lib/ipc";
import { normalizeScanAssistMode, scanModeLabel, scanModeOptions } from "@/lib/scanModes";
import { useReportStore } from "@/store/reportStore";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import type { AgentQuestion, ChatItem, ChatMessage } from "@/types/chat";
import type { DoctorProgressEvent } from "@/types/doctor";
import type { HermsecScanAssistMode } from "@/types/scan";
import type { AppSettings, AutomationFrequency, AutomationSettings } from "@/types/settings";
import { AutomationPopover } from "@/components/automation/AutomationPopover";
import { Button } from "@/components/ui/Button";
import { Composer } from "./Composer";
import { MessageList } from "./MessageList";
import { QuickActions } from "./QuickActions";

function createId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function completionMessage(label: string, summary?: { total: number; critical: number; high: number; medium: number; low: number; info: number }, pdfReady?: boolean): string {
  if (!summary) {
    return `${label} completed. The report artifacts are ready below.`;
  }

  if (summary.total === 0) {
    return [
      `${label} completed.`,
      "No findings were reported by the configured scanners for this run.",
      pdfReady ? "The final PDF is ready below." : "The report folder is ready below.",
    ].join("\n");
  }

  const severityText = [
    summary.critical ? `${summary.critical} critical` : "",
    summary.high ? `${summary.high} high` : "",
    summary.medium ? `${summary.medium} medium` : "",
    summary.low ? `${summary.low} low` : "",
    summary.info ? `${summary.info} info` : "",
  ].filter(Boolean).join(", ");

  const hook = summary.critical || summary.high
    ? "The hook: start with the critical/high items first; they are the findings most likely to carry immediate exploit or data-exposure risk."
    : "The hook: no critical/high items surfaced, so review the medium/low findings for hardening and cleanup.";

  return [
    `${label} completed.`,
    `HermSec found ${summary.total} finding${summary.total === 1 ? "" : "s"}${severityText ? `: ${severityText}` : ""}.`,
    hook,
    pdfReady ? "The final PDF and report folder are linked below." : "The report folder is linked below.",
  ].join("\n");
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        window.clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        window.clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function progressStatusText(event: DoctorProgressEvent): string {
  if (event.status === "running") return event.message;
  if (event.status === "pass") return `${event.label} is ready.`;
  if (event.status === "warn") return `${event.label} needs attention.`;
  if (event.status === "fail") return `${event.label} failed its check.`;
  return `${event.label} is not configured.`;
}

type AssistantAnswer = string | {
  content: string;
  copyAction?: ChatMessage["copyAction"];
  reportLink?: ChatMessage["reportLink"];
};
type ParsedAutomation = Pick<AutomationSettings, "frequency" | "intervalDays" | "time">;
type HermsecActionRoute = "scan" | "automation" | "capabilities" | "doctor" | "fix-prompt" | "chat";
interface ActiveHermsecAction {
  id: number;
  stop?: () => void;
}
const DOCTOR_RUN_TIMEOUT_MS = 35_000;
const SCAN_MODE_QUESTION_ID = "scan_mode";

export function ChatView() {
  const chatItems = useUiStore((s) => s.chatItems);
  const isAgentThinking = useUiStore((s) => s.isAgentThinking);
  const setChatItems = useUiStore((s) => s.setChatItems);
  const setAgentThinking = useUiStore((s) => s.setAgentThinking);
  const setAgentStatus = useUiStore((s) => s.setAgentStatus);
  const persistCurrentSession = useSessionStore((s) => s.persistCurrentSession);
  const currentSession = useSessionStore((s) => s.currentSession);
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const setView = useUiStore((s) => s.setView);
  const runScan = useReportStore((s) => s.runScan);
  const cancelScan = useReportStore((s) => s.cancelScan);
  const restartScan = useReportStore((s) => s.restartScan);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const latestReport = useReportStore((s) => s.latestReport);
  const hydrateLatest = useReportStore((s) => s.hydrateLatest);
  const [pendingAutomation, setPendingAutomation] = useState<Partial<ParsedAutomation> | null>(null);
  const actionSequenceRef = useRef(0);
  const activeActionRef = useRef<ActiveHermsecAction | null>(null);

  const hasMessages = chatItems.length > 0;
  const activeProjectPath = () =>
    useSettingsStore.getState().settings?.defaultProjectDir?.trim() ||
    useSessionStore.getState().currentSession?.projectPath?.trim() ||
    "";

  useEffect(() => {
    if (!settings?.defaultProjectDir) return;
    void hydrateLatest(settings.defaultProjectDir);
  }, [hydrateLatest, settings?.defaultProjectDir]);

  const pushMessage = async (
    role: ChatMessage["role"],
    content: string,
    reportLinkOrLinks?: ChatMessage["reportLink"] | ChatMessage["reportLinks"],
    copyAction?: ChatMessage["copyAction"],
  ) => {
    const reportLinks = Array.isArray(reportLinkOrLinks) ? reportLinkOrLinks : undefined;
    const reportLink = !Array.isArray(reportLinkOrLinks) ? reportLinkOrLinks : undefined;
    const item: ChatItem = {
      kind: "message",
      id: createId(),
      message: {
        id: createId(),
        role,
        content,
        createdAt: Date.now(),
        ...(reportLink ? { reportLink } : {}),
        ...(reportLinks ? { reportLinks } : {}),
        ...(copyAction ? { copyAction } : {}),
      },
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);
    await persistCurrentSession(
      activeProjectPath(),
      nextItems,
      role === "user" ? content : undefined,
    );
  };

  const pushQuestionItem = async (questions: AgentQuestion[]) => {
    const item: ChatItem = {
      kind: "questions",
      id: createId(),
      questions,
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);
    await persistCurrentSession(activeProjectPath(), nextItems);
  };

  const pushScanProgressItem = async () => {
    const events = useReportStore.getState().progress;
    if (events.length === 0) return;
    const item: ChatItem = {
      kind: "scan-progress",
      id: createId(),
      events,
      running: false,
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);
    await persistCurrentSession(activeProjectPath(), nextItems);
  };

  const beginAction = (status: string, stop?: () => void) => {
    const id = actionSequenceRef.current + 1;
    actionSequenceRef.current = id;
    activeActionRef.current = { id, stop };
    setAgentThinking(true);
    setAgentStatus(status);
    return id;
  };

  const isActionCurrent = (id: number) => activeActionRef.current?.id === id;

  const setActionStop = (id: number, stop: () => void) => {
    if (!isActionCurrent(id)) return;
    activeActionRef.current = { id, stop };
  };

  const finishAction = (id: number) => {
    if (!isActionCurrent(id)) return;
    activeActionRef.current = null;
    setAgentThinking(false);
    setAgentStatus("Thinking...");
  };

  const handleStopAction = () => {
    const active = activeActionRef.current;
    const shouldStopScan = useReportStore.getState().scanRunning;
    if (!active && !shouldStopScan) return;

    actionSequenceRef.current += 1;
    activeActionRef.current = null;
    if (active?.stop) {
      active.stop();
    } else if (shouldStopScan) {
      void cancelScan();
    }
    setAgentThinking(false);
    setAgentStatus("Action stopped.");
    void pushMessage("assistant", "Stopped the current action.");
  };

  const pushDoctorItem = async (actionId?: number) => {
    const api = requireHermsecApi();
    const id = createId();
    const item: ChatItem = {
      kind: "doctor",
      id,
      running: true,
      progress: [],
    };
    const nextItems = [...useUiStore.getState().chatItems, item];
    setChatItems(nextItems);

    const updateDoctorItem = (updater: (item: ChatItem) => ChatItem): ChatItem[] => {
      const updatedItems = useUiStore
        .getState()
        .chatItems.map((current) => (current.id === id ? updater(current) : current));
      setChatItems(updatedItems);
      return updatedItems;
    };

    const unsubscribe = api.doctor.onProgress((event) => {
      if (actionId && !isActionCurrent(actionId)) return;
      if (event.runId !== id) return;
      setAgentStatus(progressStatusText(event));
      updateDoctorItem((current) => {
        if (current.kind !== "doctor") return current;
        return {
          ...current,
          running: true,
          progress: [...(current.progress ?? []), event].slice(-48),
        };
      });
    });

    if (actionId) {
      setActionStop(actionId, () => {
        unsubscribe();
        const stoppedItems = updateDoctorItem((current) =>
          current.kind === "doctor"
            ? {
                ...current,
                running: false,
                error: "Doctor stopped by you.",
                progress: [
                  ...(current.progress ?? []),
                  {
                    id: "doctor-stopped",
                    runId: id,
                    groupId: "required",
                    label: "Doctor stopped",
                    status: "fail",
                    requirement: "optional",
                    message: "Doctor checks were stopped by you.",
                    at: Date.now(),
                  },
                ],
              }
            : current,
        );
        void persistCurrentSession(activeProjectPath(), stoppedItems);
      });
    }

    try {
      const result = await withTimeout(
        api.doctor.run(id),
        DOCTOR_RUN_TIMEOUT_MS,
        `Doctor did not finish within ${Math.round(DOCTOR_RUN_TIMEOUT_MS / 1000)} seconds. The run was stopped in the chat so it cannot loop forever.`,
      );
      if (actionId && !isActionCurrent(actionId)) return;
      const completedItems = updateDoctorItem((current) =>
        current.kind === "doctor"
          ? { ...current, result, running: false, error: undefined }
          : current,
      );
      setAgentStatus(result.ok ? "Doctor checks completed." : "Doctor finished with items to review.");
      await persistCurrentSession(activeProjectPath(), completedItems);
    } catch (error) {
      if (actionId && !isActionCurrent(actionId)) return;
      const message = error instanceof Error ? error.message : "Doctor could not complete.";
      const failedItems = updateDoctorItem((current) =>
        current.kind === "doctor"
          ? {
              ...current,
              running: false,
              error: message,
              progress: [
                ...(current.progress ?? []),
                {
                  id: "doctor-timeout",
                  runId: id,
                  groupId: "required",
                  label: "Doctor watchdog",
                  status: "fail",
                  requirement: "required",
                  message,
                  at: Date.now(),
                },
              ],
            }
          : current,
      );
      setAgentStatus("Doctor stopped before it could complete.");
      await persistCurrentSession(activeProjectPath(), failedItems);
    } finally {
      unsubscribe();
    }
  };

  const pushCapabilityQuestions = () =>
    pushQuestionItem([
      {
        id: "hermsec_action",
        prompt: "Choose what you want Hermsec to do next.",
        options: [
          { id: "scan_repo", label: "Scan repo", description: "Run Hermsec against the selected project." },
          { id: "set_automation", label: "Set an automation", description: "Schedule recurring scans while the app is open." },
        ],
      },
    ]);

  const pushScanModeQuestions = () =>
    pushQuestionItem([
      {
        id: SCAN_MODE_QUESTION_ID,
        prompt: "Choose how Hermsec should assist this scan.",
        options: scanModeOptions.map((option) => ({
          id: option.id,
          label: option.label,
          description: option.description,
          meta: option.status,
        })),
      },
    ]);

  const runProjectScan = async (assistModeInput?: HermsecScanAssistMode) => {
    const projectPath = activeProjectPath();
    const currentSettings = useSettingsStore.getState().settings;
    if (!projectPath) {
      await pushMessage(
        "assistant",
        "Choose a project folder first, then I can scan it. Use **New chat** or the **+** button in Projects to select the repository you want Hermsec to inspect.",
      );
      return;
    }

    const assistMode = normalizeScanAssistMode(assistModeInput ?? currentSettings?.general.scanMode);
    const label = scanModeLabel(assistMode);
    const actionId = beginAction(
      assistMode === "deep-assisted"
        ? "Starting deep assisted scan..."
        : "Starting scanner + model summary scan...",
      () => {
        void cancelScan();
      },
    );
    try {
      const result = await runScan({
        targetPath: projectPath,
        reportDir: currentSettings?.defaultReportDir,
        mode: "online",
        assistMode,
        useModel: true,
      });
      if (!isActionCurrent(actionId)) return;

      if (!result.ok) {
        if (result.canceled) {
          await pushScanProgressItem();
          await pushMessage("assistant", "Scan stopped.");
          return;
        }
        await pushMessage("assistant", `Scan failed. ${result.message}`);
        return;
      }

      await pushScanProgressItem();

      const reportLinks: ChatMessage["reportLinks"] = [
        ...(result.onepagerPdfPath ? [{ label: "Open final PDF location", path: result.onepagerPdfPath }] : []),
        ...(result.reportDir ? [{ label: "Open report folder", path: result.reportDir }] : []),
      ];
      await pushMessage(
        "assistant",
        completionMessage(label, result.summary, Boolean(result.onepagerPdfPath)),
        reportLinks.length > 0 ? reportLinks : undefined,
      );
    } catch (error) {
      if (!isActionCurrent(actionId)) return;
      const message = error instanceof Error ? error.message : "Hermsec could not complete the scan.";
      await pushMessage("assistant", `Scan failed. ${message}`);
    } finally {
      finishAction(actionId);
    }
  };

  const saveAutomation = async (partial: Partial<ParsedAutomation>) => {
    const currentSettings = useSettingsStore.getState().settings;
    const frequency = partial.frequency ?? "custom-days";
    const intervalDays = frequency === "custom-days" ? normalizeIntervalDays(partial.intervalDays) : undefined;
    const time = partial.time ?? "09:00";

    await updateSettings({
      automation: {
        ...currentSettings?.automation,
        enabled: true,
        frequency,
        ...(intervalDays ? { intervalDays } : {}),
        time,
      },
    });

    setPendingAutomation(null);
    await pushMessage(
      "assistant",
      [
        `Done. I set the Hermsec scan automation to run ${formatAutomationFrequency({ frequency, intervalDays })} at ${formatClockTime(time)}.`,
        "It runs only while Hermsec is open. When it is due, Hermsec checks whether the selected project changed; if nothing changed, it skips the scan.",
      ].join("\n"),
    );
  };

  const continueAutomationFlow = async (partial: Partial<ParsedAutomation>) => {
    const missingFrequency = !partial.frequency;
    const missingTime = !partial.time;

    if (!missingFrequency && !missingTime) {
      await saveAutomation(partial);
      return;
    }

    setPendingAutomation(partial);
    await pushMessage(
      "assistant",
      missingFrequency && missingTime
        ? "I can set that up. I just need the scan cadence and exact run time."
        : missingFrequency
          ? "I have the time. How often should Hermsec run this scan?"
          : "I have the cadence. What time should Hermsec run it?",
    );
    await pushQuestionItem(buildAutomationQuestions(partial));
  };

  const handleAutomationRequest = async (text: string) => {
    const parsed = parseAutomationRequest(text);
    await continueAutomationFlow(parsed);
  };

  const handleSend = async (text: string) => {
    await pushMessage("user", text);
    const actionId = beginAction("Understanding your request...", () => {
      void requireHermsecApi().reports.cancel();
    });

    try {
      const currentItems = useUiStore.getState().chatItems;
      const latestReportPath = latestReport?.htmlPath ?? findLatestReportPath(currentItems);
      if (pendingAutomation) {
        setAgentStatus("Finishing the automation setup...");
        await continueAutomationFlow({
          ...pendingAutomation,
          ...parseAutomationRequest(text),
        });
        if (!isActionCurrent(actionId)) return;
        return;
      }

      const route = classifyHermsecAction(text, currentItems);
      if (route === "scan") {
        setAgentStatus("Preparing scan mode choices...");
        await pushScanModeQuestions();
        if (!isActionCurrent(actionId)) return;
        return;
      }

      if (route === "automation") {
        setAgentStatus("Planning a scan automation...");
        await handleAutomationRequest(text);
        if (!isActionCurrent(actionId)) return;
        return;
      }

      if (route === "capabilities") {
        setAgentStatus("Preparing Hermsec capabilities...");
        await pushMessage(
          "assistant",
          "I can scan this repo, explain the findings in plain language, show you where issues sit in code, help prioritize fixes, generate a fix prompt for another coding agent, and set an in-app scan automation.",
        );
        await pushCapabilityQuestions();
        if (!isActionCurrent(actionId)) return;
        return;
      }

      if (route === "doctor") {
        setAgentStatus("Checking scanner tools and internet sources...");
        await pushDoctorItem(actionId);
        if (!isActionCurrent(actionId)) return;
        return;
      }

      setAgentStatus(route === "fix-prompt" ? "Preparing a scanner-backed fix prompt..." : agentModelStatus(settings));
      const response = await answerSecurityQuestion(text, latestReportPath, activeProjectPath(), currentItems);
      if (!isActionCurrent(actionId)) return;
      const answer = normalizeAssistantAnswer(response);
      await pushMessage("assistant", answer.content, answer.reportLink, answer.copyAction);
    } catch (error) {
      if (!isActionCurrent(actionId)) return;
      await pushMessage(
        "assistant",
        error instanceof Error ? `Hermsec could not complete that action. ${error.message}` : "Hermsec could not complete that action.",
      );
    } finally {
      finishAction(actionId);
    }
  };

  const handleQuickAction = (action: string) => {
    if (action === "Doctor") {
      void handleSend("Run Hermsec Doctor checks");
      return;
    }
    void handleSend(`Run ${action.toLowerCase()} for the current project`);
  };

  const handleQuestionSubmit = (answers: Record<string, string[]>) => {
    const action = answers.hermsec_action?.[0];
    if (action === "scan_repo") {
      void pushScanModeQuestions();
      return;
    }
    if (action === "set_automation") {
      void continueAutomationFlow({});
      setView("chat");
      return;
    }

    const selectedScanMode = answers[SCAN_MODE_QUESTION_ID]?.[0];
    if (selectedScanMode) {
      const assistMode = normalizeScanAssistMode(selectedScanMode);
      void (async () => {
        const currentSettings = useSettingsStore.getState().settings;
        if (currentSettings) {
          await updateSettings({
            general: {
              ...currentSettings.general,
              scanMode: assistMode,
            },
          });
        }
        await runProjectScan(assistMode);
      })();
      return;
    }

    if (answers.automation_frequency || answers.automation_time) {
      const selected = parseAutomationAnswers(answers);
      void continueAutomationFlow({
        ...(pendingAutomation ?? {}),
        ...selected,
      });
    }
  };

  return (
    <div className="relative flex h-full min-h-0 flex-col overflow-hidden">
      <ChatTopActions title={currentSession?.title || "hermsec"} />
      <AnimatePresence>
        {hasMessages && (
          <motion.div
            key="messages"
            className="min-h-0 flex-1 overflow-hidden"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <MessageList onQuestionsSubmit={handleQuestionSubmit} />
          </motion.div>
        )}
      </AnimatePresence>

      <div
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

        <div className="w-full">
          {hasMessages && !scanRunning && !isAgentThinking ? (
            <QuickActions
              compact
              className="mb-2 justify-start px-1"
              onAction={handleQuickAction}
            />
          ) : null}
          <Composer
            onSend={handleSend}
            disabled={isAgentThinking}
            busy={isAgentThinking || scanRunning}
            scanRunning={scanRunning}
            compact={hasMessages}
            onStop={handleStopAction}
            onRestartScan={() => {
              void restartScan();
            }}
          />
        </div>
      </div>
    </div>
  );
}

function classifyHermsecAction(text: string, chatItems: ChatItem[]): HermsecActionRoute {
  const lower = text.toLowerCase();
  if (isDoctorRequest(lower)) return "doctor";
  if (isScanRequestText(lower)) return "scan";
  if (isAutomationRequest(lower)) return "automation";
  if (wantsCapabilities(lower)) return "capabilities";
  if (wantsFixPrompt(lower) || wantsPromptRevision(lower, findLatestFixPrompt(chatItems))) return "fix-prompt";
  return "chat";
}

function isScanRequestText(lower: string): boolean {
  if (/^(what|which|why|how|explain|summarize|show me|tell me)\b/.test(lower)) {
    return false;
  }
  return /\b(scan|rescan)\b/.test(lower) || /\b(run|start|perform)\s+(a\s+)?scan\b/.test(lower);
}

function isDoctorRequest(lower: string): boolean {
  return /\b(doctor|readiness|tool readiness|scanner readiness|check tools|internet connectivity|network check)\b/.test(lower);
}

function findLatestReportPath(chatItems: ChatItem[]): string | undefined {
  for (const item of [...chatItems].reverse()) {
    if (item.kind === "message" && item.message.reportLink?.path.endsWith("report.html")) {
      return item.message.reportLink.path;
    }
  }
  return undefined;
}

function ChatTopActions({ title }: { title: string }) {
  const [automationOpen, setAutomationOpen] = useState(false);
  const latestReport = useReportStore((s) => s.latestReport);
  const view = useUiStore((s) => s.view);
  const setView = useUiStore((s) => s.setView);
  const renderActions = () => (
    <ActionCluster
      automationOpen={automationOpen}
      latestReportReady={Boolean(latestReport?.dashboardHtmlPath)}
      view={view}
      onDashboard={() => setView("dashboard")}
      onToggleAutomation={() => setAutomationOpen((open) => !open)}
      onCloseAutomation={() => setAutomationOpen(false)}
    />
  );

  return (
    <>
      <div className="absolute inset-x-0 top-0 z-30 flex h-12 items-center justify-between border-b border-border-subtle bg-background/95 px-4 backdrop-blur xl:hidden">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-semibold text-foreground">{title}</span>
          <span className="text-lg leading-none text-muted">...</span>
        </div>
        {renderActions()}
      </div>
      <div className="absolute right-4 top-3 z-30 hidden xl:block">{renderActions()}</div>
    </>
  );
}

function ActionCluster({
  automationOpen,
  latestReportReady,
  view,
  onDashboard,
  onToggleAutomation,
  onCloseAutomation,
}: {
  automationOpen: boolean;
  latestReportReady: boolean;
  view: string;
  onDashboard: () => void;
  onToggleAutomation: () => void;
  onCloseAutomation: () => void;
}) {
  return (
    <div className="relative flex items-center gap-1 rounded-lg border border-border/70 bg-background/80 p-1 shadow-[0_10px_35px_rgba(0,0,0,0.28)] backdrop-blur">
      <Button
        variant={view === "dashboard" ? "subtle" : "ghost"}
        size="icon"
        title={latestReportReady ? "Open dashboard" : "Run a scan to enable dashboard"}
        disabled={!latestReportReady}
        onClick={onDashboard}
      >
        <LayoutDashboard className="h-3.5 w-3.5" />
      </Button>
      <Button
        variant={automationOpen ? "subtle" : "ghost"}
        size="icon"
        title="Automation"
        onClick={onToggleAutomation}
      >
        <Clock className="h-3.5 w-3.5" />
      </Button>
      <AutomationPopover open={automationOpen} onClose={onCloseAutomation} />
    </div>
  );
}

async function answerSecurityQuestion(
  text: string,
  latestReportPath?: string,
  projectPath?: string,
  chatItems: ChatItem[] = [],
): Promise<AssistantAnswer> {
  const lower = text.toLowerCase();
  const previousPrompt = findLatestFixPrompt(chatItems);
  const promptFollowUp = wantsPromptRevision(lower, previousPrompt);

  if (wantsCapabilities(lower)) {
    return [
      "I can help with Hermsec security work for this project:",
      "1. Run the full online scan pipeline for the selected repo.",
      "2. Explain the latest HTML report and summarize the real findings.",
      "3. Prioritize fixes by severity, secrets exposure, and exploitability.",
      "4. Talk through remediation steps and what to rerun after patching.",
      "5. Help configure report folders, model/provider settings, and project sessions.",
      "",
      "Ask me to scan the project, explain the latest report, list the highest-risk findings, or suggest what to fix first.",
    ].join("\n");
  }

  if (wantsFixPrompt(lower) || promptFollowUp) {
    if (!latestReportPath) {
      return "I can write that fix prompt after I have scan evidence. Run `Scan project` first, then ask me for a prompt for another coding agent.";
    }

    const result = await requireHermsecApi().reports.explain({
      reportPath: latestReportPath,
      question: promptFollowUp
        ? `Create another version of the previous fix prompt. User revision request: ${text}`
        : text,
      ...(previousPrompt ? { previousPrompt } : {}),
    });
    return result.ok
      ? {
          content: result.message,
          ...(result.copyText
            ? {
                copyAction: {
                  label: result.copyLabel ?? "Copy",
                  text: result.copyText,
                },
              }
            : {}),
          ...(result.promptFilePath
            ? {
                reportLink: {
                  label: "Open prompt file in File Explorer",
                  path: result.promptFilePath,
                },
              }
            : {}),
        }
      : `I found the latest report reference, but could not explain it yet. ${result.message}`;
  }

  const result = await requireHermsecApi().reports.converse({
    reportPath: latestReportPath,
    projectPath,
    question: text,
    history: buildConversationHistory(chatItems),
  });
  return result.ok
    ? result.message
    : `I could not reach the model cleanly yet. ${result.message}`;
}

function wantsCapabilities(text: string): boolean {
  return /\b(what can you do|help|capabilities|commands|how do you work)\b/.test(text);
}

function wantsReportExplanation(text: string): boolean {
  return /\b(report|html|scan|scanned|found|finding|findings|summary|explain|severity|critical|high|medium|secret|token|fix|remediate|priority|prioritize|where|file|line|code|location|prompt|another agent|coding agent)\b/.test(text);
}

function wantsFixPrompt(text: string): boolean {
  return /\b(prompt|copy prompt|another agent|coding agent|fixing agent|send .*agent|agent .*fix)\b/.test(text);
}

function wantsPromptRevision(text: string, previousPrompt?: string): boolean {
  if (!previousPrompt) return false;
  return /\b(update|revise|revision|rewrite|improve|another version|new version|break it down|split it|phases?|stages?|step by step|make it)\b/.test(text);
}

function isSecurityScoped(text: string): boolean {
  return /\b(security|vulnerab|cve|cwe|secret|token|credential|injection|xss|csrf|xsrf|sql|command|eval|dependency|supply chain|npm|package|risk|threat|exploit|patch|remediate|repo|project|walk me through|issue|issues)\b/.test(text);
}

function looksLikeReportFollowUp(text: string): boolean {
  return /\b(yes|no|have you|did you|what about|which one|where|why|how|show|tell|explain|fix|next|issue|issues|line|code|file|scan|scanned)\b/.test(text);
}

function normalizeAssistantAnswer(answer: AssistantAnswer): {
  content: string;
  copyAction?: ChatMessage["copyAction"];
  reportLink?: ChatMessage["reportLink"];
} {
  return typeof answer === "string" ? { content: answer } : answer;
}

function agentModelStatus(settings: AppSettings | null): string {
  const activeModelId = settings?.activeModelId;
  const activeProviderId = settings?.activeProviderId;
  const modelOptions = settings?.providers
    .filter((provider) => provider.enabled)
    .flatMap((provider) =>
      provider.models.map((model) => ({ ...model, providerId: provider.id, provider: provider.displayName })),
    ) ?? [];
  const activeModel =
    modelOptions.find((model) => model.enabled && model.id === activeModelId && model.providerId === activeProviderId) ??
    modelOptions.find((model) => model.enabled && model.id === activeModelId);

  if (activeModel) {
    return `Reading report evidence and asking ${activeModel.label} (${thinkingLabel(settings?.general.thinkingLevel)})...`;
  }

  return "Reading report evidence and preparing a security answer...";
}

function thinkingLabel(level: string | undefined): string {
  if (level === "fast") return "Fast";
  if (level === "deep") return "Deep";
  return "Balanced";
}

function buildConversationHistory(chatItems: ChatItem[]) {
  return chatItems
    .filter((item): item is Extract<ChatItem, { kind: "message" }> => item.kind === "message")
    .slice(-10)
    .map((item) => ({
      role: item.message.role,
      content: item.message.content,
    }));
}

function findLatestFixPrompt(chatItems: ChatItem[]): string | undefined {
  for (const item of [...chatItems].reverse()) {
    if (item.kind !== "message") continue;
    const copyAction = item.message.copyAction;
    if (!copyAction?.text) continue;
    const label = copyAction.label.toLowerCase();
    if (label.includes("prompt") || copyAction.text.startsWith("You are a defensive security coding agent")) {
      return copyAction.text;
    }
  }
  return undefined;
}

function isAutomationRequest(text: string): boolean {
  const lower = text.toLowerCase();
  return /\b(automation|automate|schedule|cron|recurring|daily|weekly|monthly|every\s+\d+\s+days?)\b/.test(lower) &&
    /\b(scan|security|repo|project|run|set|create|enable|make|setup|configure|for me)\b/.test(lower);
}

function buildAutomationQuestions(partial: Partial<ParsedAutomation>): AgentQuestion[] {
  const questions: AgentQuestion[] = [];
  if (!partial.frequency) {
    questions.push({
      id: "automation_frequency",
      prompt: "How often should Hermsec scan this project?",
      options: [
        { id: "days:1", label: "Every day" },
        { id: "days:3", label: "Every 3 days" },
        { id: "weekly", label: "Every week" },
        { id: "monthly", label: "Every month" },
      ],
    });
  }
  if (!partial.time) {
    questions.push({
      id: "automation_time",
      prompt: "What time should it run?",
      options: [
        { id: "09:00", label: "09:00 AM" },
        { id: "12:00", label: "12:00 PM" },
        { id: "18:00", label: "06:00 PM" },
        { id: "21:00", label: "09:00 PM" },
      ],
    });
  }
  return questions;
}

function parseAutomationAnswers(answers: Record<string, string[]>): Partial<ParsedAutomation> {
  const parsed: Partial<ParsedAutomation> = {};
  const frequency = answers.automation_frequency?.[0];
  const time = answers.automation_time?.[0];

  if (frequency?.startsWith("days:")) {
    parsed.frequency = "custom-days";
    parsed.intervalDays = normalizeIntervalDays(Number(frequency.split(":")[1]));
  } else if (frequency === "weekly" || frequency === "monthly") {
    parsed.frequency = frequency;
  }

  if (time && /^\d{2}:\d{2}$/.test(time)) {
    parsed.time = time;
  }

  return parsed;
}

function parseAutomationRequest(text: string): Partial<ParsedAutomation> {
  const lower = text.toLowerCase();
  const parsed: Partial<ParsedAutomation> = {};
  const everyDays = lower.match(/\bevery\s+(\d{1,3})\s+days?\b/);

  if (everyDays) {
    parsed.frequency = "custom-days";
    parsed.intervalDays = normalizeIntervalDays(Number(everyDays[1]));
  } else if (/\b(every\s+day|daily|each\s+day)\b/.test(lower)) {
    parsed.frequency = "custom-days";
    parsed.intervalDays = 1;
  } else if (/\b(every\s+week|weekly|each\s+week)\b/.test(lower)) {
    parsed.frequency = "weekly";
  } else if (/\b(every\s+month|monthly|each\s+month)\b/.test(lower)) {
    parsed.frequency = "monthly";
  }

  const parsedTime = parseTimeText(lower);
  if (parsedTime) {
    parsed.time = parsedTime;
  }

  return parsed;
}

function parseTimeText(text: string): string | undefined {
  const twelveHour = text.match(/\b(?:at\s*)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/);
  if (twelveHour) {
    let hours = Number(twelveHour[1]);
    const minutes = Number(twelveHour[2] ?? "0");
    if (hours < 1 || hours > 12 || minutes < 0 || minutes > 59) return undefined;
    const suffix = twelveHour[3];
    if (suffix === "pm" && hours !== 12) hours += 12;
    if (suffix === "am" && hours === 12) hours = 0;
    return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
  }

  const twentyFourHour = text.match(/\b([01]?\d|2[0-3]):([0-5]\d)\b/);
  if (twentyFourHour) {
    return `${String(Number(twentyFourHour[1])).padStart(2, "0")}:${twentyFourHour[2]}`;
  }

  return undefined;
}

function normalizeIntervalDays(value: number | undefined): number {
  if (!Number.isFinite(Number(value))) return 1;
  return Math.min(365, Math.max(1, Math.floor(Number(value))));
}

function formatAutomationFrequency({
  frequency,
  intervalDays,
}: {
  frequency: AutomationFrequency;
  intervalDays?: number;
}): string {
  if (frequency === "weekly") return "every week";
  if (frequency === "monthly") return "every month";
  const days = normalizeIntervalDays(intervalDays);
  return days === 1 ? "every day" : `every ${days} days`;
}

function formatClockTime(value: string): string {
  const [hourText, minuteText] = value.split(":");
  const hours = Number(hourText);
  const minutes = Number(minuteText);
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return value;
  const suffix = hours >= 12 ? "PM" : "AM";
  const hour12 = hours % 12 || 12;
  return `${hour12}:${String(minutes).padStart(2, "0")} ${suffix}`;
}
