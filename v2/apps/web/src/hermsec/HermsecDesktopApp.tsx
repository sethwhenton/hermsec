import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { HermsecJsonCommandResult } from "@t3tools/contracts";
import {
  Sidebar,
  SIDEBAR_OFFCANVAS_MOTION_CLASS,
  SidebarInstanceProvider,
  SidebarProvider,
  SidebarRail,
} from "~/components/ui/sidebar";
import { cn } from "~/lib/utils";
import { useTheme } from "~/hooks/useTheme";
import {
  DEFAULT_HERMSEC_SETTINGS,
  MOCK_AUTOMATIONS,
  MOCK_PROJECTS,
  MOCK_REPORTS,
} from "./mockData";
import type {
  HermsecAutomation,
  HermsecChatChoice,
  HermsecChatMessage,
  HermsecMainView,
  HermsecProject,
  HermsecReportPreview,
  HermsecSettingsState,
} from "./types";
import { HermsecLeftSidebar } from "./components/HermsecLeftSidebar";
import { HermsecMainSurface } from "./components/HermsecMainSurface";
import { HermsecRightPanel } from "./components/HermsecRightPanel";
import { HermsecStatusBar } from "./components/HermsecStatusBar";

const LEFT_SIDEBAR_RESIZABLE = {
  minWidth: 176,
  maxWidth: 280,
  storageKey: "hermsec:left-sidebar-width",
} as const;

const SIDEBAR_GAP_CLASS =
  "overflow-hidden before:absolute before:inset-0 before:bg-[linear-gradient(180deg,rgba(255,255,255,0.018),rgba(255,255,255,0.006))]";

const SIDEBAR_INNER_CLASS =
  "app-sidebar-surface border-r border-[color:var(--app-surface-divider)]";

const FALLBACK_CHOICES: HermsecChatChoice[] = [
  {
    id: "scan-repo",
    label: "Scan repo",
    description: "Run the Hermsec harness on the active local project.",
    action: "scan-repo",
  },
  {
    id: "set-automation",
    label: "Set an automation",
    description: "Create a scheduled scan that checks git changes before running.",
    action: "set-automation",
  },
];

type BridgeConfig = {
  privacyMode?: string;
  customReportDir?: string;
  preferredModelProvider?: string;
  providerCredentialRef?: {
    kind?: string;
    name?: string;
  };
};

type BridgeReportEntry = {
  scanId: string;
  generatedAt?: string;
  reportDir?: string;
  htmlPath?: string;
  totals?: {
    total?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
};

type BridgeScheduleRecord = {
  id: string;
  targetPath: string;
  enabled: boolean;
  trigger?: string;
  time?: string;
  cron?: string;
  mode?: HermsecSettingsState["scanMode"];
  nextRunAt?: string;
  lastRunAt?: string;
  lastStatus?: "success" | "partial" | "skipped" | "failed" | "blocked";
};

type BridgeStateData = {
  homeDir?: string;
  model?: string;
  baseUrl?: string;
  config?: BridgeConfig | null;
  reports?: BridgeReportEntry[];
  schedules?: BridgeScheduleRecord[];
  reportDirectory?: string | null;
};

type BridgeScanData = {
  scan?: {
    id?: string;
    target?: string;
    summary?: {
      total?: number;
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
      info?: number;
    };
  };
  report?: {
    htmlPath?: string;
    markdownPath?: string;
    summaryPath?: string;
    directory?: string;
  };
};

function messageId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function basename(value: string): string {
  const normalized = value.replace(/\\/g, "/").replace(/\/+$/, "");
  return normalized.split("/").pop() || normalized || "Project";
}

function formatDateLabel(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function dailyTimeFromSettings(value: string): string {
  return value.match(/(\d{2}:\d{2})/)?.[1] ?? "09:00";
}

function riskFromTotals(total = 0, high = 0, critical = 0): HermsecProject["riskLevel"] {
  if (critical > 0 || high > 0 || total >= 8) return "high";
  if (total > 0) return "medium";
  return "low";
}

function mapScheduleStatus(status?: BridgeScheduleRecord["lastStatus"]): HermsecAutomation["lastResult"] {
  if (status === "success" || status === "partial") return "success";
  if (status === "failed" || status === "blocked") return "failed";
  return "idle";
}

function mapSchedule(record: BridgeScheduleRecord, reportDirectory: string): HermsecAutomation {
  const scheduleLabel =
    record.trigger === "cron"
      ? `Cron - ${record.cron ?? "* * * * *"}`
      : `${record.trigger ?? "Daily"} - ${record.time ?? "09:00"}`;
  return {
    id: record.id,
    name: `${basename(record.targetPath)} security scan`,
    schedule: scheduleLabel,
    targetProject: basename(record.targetPath),
    nextRun: formatDateLabel(record.nextRunAt),
    ...(record.nextRunAt ? { nextRunAt: record.nextRunAt } : {}),
    lastResult: mapScheduleStatus(record.lastStatus),
    reportFolder: reportDirectory,
    enabled: record.enabled,
  };
}

function mapReportPreview(report: BridgeReportEntry): HermsecReportPreview {
  return {
    id: report.scanId,
    title: `${report.scanId} report`,
    path: report.htmlPath ?? report.reportDir ?? report.scanId,
    html: "",
  };
}

function extractScanData(result?: HermsecJsonCommandResult | null): BridgeScanData | null {
  const data = result?.parsed?.data;
  return isRecord(data) ? (data as BridgeScanData) : null;
}

function reportPreviewFromOpenResult(
  result: HermsecJsonCommandResult,
  fallback: HermsecReportPreview,
): HermsecReportPreview {
  const data = result.parsed?.data;
  const html = isRecord(data) && typeof data.html === "string" ? data.html : fallback.html;
  const path = isRecord(data) && typeof data.path === "string" ? data.path : fallback.path;
  const report = isRecord(data) && isRecord(data.report) ? data.report : null;
  const title =
    report && typeof report.scanId === "string" ? `${report.scanId} report` : fallback.title;
  return {
    ...fallback,
    title,
    path,
    html,
  };
}

function mergeProjectPaths(projects: HermsecProject[], paths: string[]): HermsecProject[] {
  const byPath = new Map(projects.map((project) => [project.path, project]));
  for (const projectPath of paths) {
    if (!projectPath || byPath.has(projectPath)) continue;
    const project: HermsecProject = {
      id: `proj-${projectPath}`,
      name: basename(projectPath),
      path: projectPath,
      lastScan: "Not scanned",
      findingCount: 0,
      riskLevel: "low",
    };
    byPath.set(project.path, project);
  }
  return [...byPath.values()];
}

export function HermsecDesktopApp() {
  useTheme();

  const [activeView, setActiveView] = useState<HermsecMainView>("chat");
  const [messages, setMessages] = useState<HermsecChatMessage[]>([]);
  const [automations, setAutomations] = useState<HermsecAutomation[]>(MOCK_AUTOMATIONS);
  const [projects, setProjects] = useState<HermsecProject[]>(MOCK_PROJECTS);
  const [settings, setSettings] = useState(DEFAULT_HERMSEC_SETTINGS);
  const [activeProjectId, setActiveProjectId] = useState(MOCK_PROJECTS[1]?.id);
  const [rightPanelOpen, setRightPanelOpen] = useState(false);
  const [reportPreview, setReportPreview] = useState<HermsecReportPreview | null>(null);
  const [agentStatus, setAgentStatus] = useState("Agent ready");
  const [bridgeReady, setBridgeReady] = useState(false);
  const automationRunsRef = useRef(new Set<string>());

  const activeProject = useMemo(
    () => projects.find((project) => project.id === activeProjectId) ?? projects[0],
    [activeProjectId, projects],
  );

  const appendAssistant = useCallback((content: string, choices?: HermsecChatChoice[]) => {
    setMessages((current) => [
      ...current,
      {
        id: messageId("assistant"),
        role: "assistant",
        content,
        ...(choices?.length ? { choices } : {}),
      },
    ]);
  }, []);

  const updateProjectFromScan = useCallback((result?: HermsecJsonCommandResult | null) => {
    const data = extractScanData(result);
    const target = data?.scan?.target;
    const summary = data?.scan?.summary;
    if (!target || !summary) return;
    setProjects((current) =>
      current.map((project) =>
        project.path === target
          ? {
              ...project,
              lastScan: "Just now",
              findingCount: summary.total ?? 0,
              riskLevel: riskFromTotals(summary.total, summary.high, summary.critical),
            }
          : project,
      ),
    );
  }, []);

  const openLatestReport = useCallback(async () => {
    const bridge = window.desktopBridge?.hermsec;
    if (!bridge) {
      const report = MOCK_REPORTS[0];
      if (report) setReportPreview(report);
      setRightPanelOpen(true);
      return;
    }
    const fallback: HermsecReportPreview = {
      id: "latest",
      title: "Latest report",
      path: "latest",
      html: "",
    };
    const result = await bridge.openReport({ selector: "latest" });
    if (!result.ok) {
      appendAssistant(result.parsed?.message ?? "No saved Hermsec report was found yet.");
      return;
    }
    setReportPreview(reportPreviewFromOpenResult(result, fallback));
    setRightPanelOpen(true);
  }, [appendAssistant]);

  const hydrateHermsecState = useCallback(async () => {
    const bridge = window.desktopBridge?.hermsec;
    if (!bridge) {
      setBridgeReady(false);
      return;
    }
    const result = await bridge.getState();
    const state = isRecord(result.parsed?.data) ? (result.parsed?.data as BridgeStateData) : null;
    setBridgeReady(true);
    if (!state) return;

    const reportDirectory =
      typeof state.reportDirectory === "string"
        ? state.reportDirectory
        : state.config?.customReportDir ?? DEFAULT_HERMSEC_SETTINGS.defaultReportDirectory;
    const schedules = Array.isArray(state.schedules) ? state.schedules : [];
    const reports = Array.isArray(state.reports) ? state.reports : [];

    setSettings((current) => ({
      ...current,
      provider: state.config?.preferredModelProvider ?? current.provider,
      model: state.model ?? current.model,
      baseUrl: state.baseUrl ?? current.baseUrl,
      apiKeyEnvVar: state.config?.providerCredentialRef?.name ?? current.apiKeyEnvVar,
      defaultReportDirectory: reportDirectory,
      privacyMode:
        state.config?.privacyMode === undefined
          ? current.privacyMode
          : state.config.privacyMode === "local-only",
    }));

    setAutomations(schedules.map((schedule) => mapSchedule(schedule, reportDirectory)));
    setProjects((current) => {
      const scanProjectPaths = reports
        .map((report) => report.reportDir)
        .filter((value): value is string => typeof value === "string");
      const scheduleProjectPaths = schedules.map((schedule) => schedule.targetPath);
      const next = mergeProjectPaths(current, scheduleProjectPaths);
      return mergeProjectPaths(next, scanProjectPaths);
    });
  }, []);

  useEffect(() => {
    void hydrateHermsecState();
  }, [hydrateHermsecState]);

  useEffect(() => {
    const onMenuAction = window.desktopBridge?.onMenuAction;
    if (typeof onMenuAction !== "function") {
      return;
    }
    return onMenuAction((action) => {
      if (action === "open-settings") {
        setActiveView("settings");
      }
    });
  }, []);

  useEffect(() => {
    const bridge = window.desktopBridge?.hermsec;
    if (!bridge || !bridgeReady) return;
    const interval = window.setInterval(() => {
      const now = Date.now();
      for (const automation of automations) {
        if (!automation.enabled || !automation.nextRunAt) continue;
        const dueAt = Date.parse(automation.nextRunAt);
        if (Number.isNaN(dueAt) || dueAt > now) continue;
        if (automationRunsRef.current.has(automation.id)) continue;
        automationRunsRef.current.add(automation.id);
        setAutomations((current) =>
          current.map((item) =>
            item.id === automation.id ? { ...item, lastResult: "running" } : item,
          ),
        );
        void bridge
          .runSchedule({ id: automation.id })
          .then((result) => {
            appendAssistant(result.parsed?.message ?? "Scheduled scan completed.");
          })
          .finally(() => {
            automationRunsRef.current.delete(automation.id);
            void hydrateHermsecState();
          });
      }
    }, 60_000);
    return () => window.clearInterval(interval);
  }, [appendAssistant, automations, bridgeReady, hydrateHermsecState]);

  const runActiveScan = useCallback(async () => {
    if (!activeProject) {
      appendAssistant("Add or select a project folder first, then I can scan it.", FALLBACK_CHOICES);
      return;
    }
    const bridge = window.desktopBridge?.hermsec;
    if (!bridge) {
      appendAssistant("Hermsec desktop bridge is unavailable in this preview environment.", FALLBACK_CHOICES);
      return;
    }
    setActiveView("chat");
    setAgentStatus("Scanning");
    setMessages((current) => [
      ...current,
      {
        id: messageId("user"),
        role: "user",
        content: `Scan repo: ${activeProject.name}`,
      },
    ]);
    try {
      const result = await bridge.scan({
        target: activeProject.path,
        mode: settings.scanMode,
        outputDirectory: settings.defaultReportDirectory,
        useModel: !settings.privacyMode && settings.scanMode !== "offline",
      });
      updateProjectFromScan(result);
      appendAssistant(result.parsed?.message ?? (result.ok ? "Scan completed." : "Scan failed."));
      if (result.ok) {
        await hydrateHermsecState();
        await openLatestReport();
      }
    } catch (error) {
      appendAssistant(error instanceof Error ? error.message : "Scan failed.");
    } finally {
      setAgentStatus("Agent ready");
    }
  }, [
    activeProject,
    appendAssistant,
    hydrateHermsecState,
    openLatestReport,
    settings.defaultReportDirectory,
    settings.privacyMode,
    settings.scanMode,
    updateProjectFromScan,
  ]);

  const handleNewChat = useCallback(() => {
    setMessages([]);
    setActiveView("chat");
  }, []);

  const handleSendMessage = useCallback(
    async (content: string) => {
      const userMessage: HermsecChatMessage = {
        id: messageId("user"),
        role: "user",
        content,
      };
      setMessages((current) => [...current, userMessage]);

      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) {
        appendAssistant(
          "I can help scan repos or set automations once the Electron bridge is available.",
          FALLBACK_CHOICES,
        );
        return;
      }

      setAgentStatus("Thinking");
      try {
        const result = await bridge.chat({
          content,
          target: activeProject?.path,
          mode: settings.scanMode,
          outputDirectory: settings.defaultReportDirectory,
          useModel: !settings.privacyMode && settings.scanMode !== "offline",
        });
        updateProjectFromScan(result.commandResult);
        appendAssistant(result.message, result.choices);
        if (result.commandResult?.ok) {
          await hydrateHermsecState();
        }
      } catch (error) {
        appendAssistant(error instanceof Error ? error.message : "Hermsec could not complete that action.");
      } finally {
        setAgentStatus("Agent ready");
      }
    },
    [
      activeProject?.path,
      appendAssistant,
      hydrateHermsecState,
      settings.defaultReportDirectory,
      settings.privacyMode,
      settings.scanMode,
      updateProjectFromScan,
    ],
  );

  const createAutomation = useCallback(async () => {
    if (!activeProject) {
      appendAssistant("Select a project before creating an automation.", FALLBACK_CHOICES);
      return;
    }
    const bridge = window.desktopBridge?.hermsec;
    setActiveView("automation");
    if (!bridge) {
      appendAssistant("Hermsec desktop bridge is unavailable, so I cannot persist an automation yet.");
      return;
    }
    setAgentStatus("Saving automation");
    try {
      const result = await bridge.addSchedule({
        target: activeProject.path,
        dailyTime: dailyTimeFromSettings(settings.automationDefaultSchedule),
        mode: settings.scanMode,
      });
      appendAssistant(result.parsed?.message ?? "Automation created.");
      await hydrateHermsecState();
    } catch (error) {
      appendAssistant(error instanceof Error ? error.message : "Automation creation failed.");
    } finally {
      setAgentStatus("Agent ready");
    }
  }, [
    activeProject,
    appendAssistant,
    hydrateHermsecState,
    settings.automationDefaultSchedule,
    settings.scanMode,
  ]);

  const handleChoice = useCallback(
    (choice: HermsecChatChoice) => {
      if (choice.action === "scan-repo") {
        void runActiveScan();
        return;
      }
      if (choice.action === "set-automation") {
        void createAutomation();
      }
    },
    [createAutomation, runActiveScan],
  );

  const handleQuickAction = useCallback(
    (actionId: string) => {
      if (actionId === "scan") {
        void runActiveScan();
        return;
      }
      if (actionId === "automations") {
        setActiveView("automation");
        return;
      }
      if (actionId === "reports") {
        void openLatestReport();
        return;
      }
      if (actionId === "doctor") {
        void handleSendMessage("Run doctor checks.");
        return;
      }
      handleSendMessage(
        `Explain ${activeProject?.name ?? "the active project"} and identify security-sensitive areas.`,
      );
    },
    [activeProject?.name, handleSendMessage, openLatestReport, runActiveScan],
  );

  const handleOpenReport = useCallback(
    async (report: HermsecReportPreview) => {
      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) {
        const resolved = MOCK_REPORTS.find((item) => item.path === report.path) ?? report;
        setReportPreview(resolved);
        setRightPanelOpen(true);
        return;
      }
      const result = await bridge.openReport({ selector: report.id || report.path });
      if (!result.ok && report.path) {
        setReportPreview(report);
      } else {
        setReportPreview(reportPreviewFromOpenResult(result, report));
      }
      setRightPanelOpen(true);
    },
    [],
  );

  const handleToggleAutomation = useCallback(
    (id: string, enabled: boolean) => {
      setAutomations((current) =>
        current.map((automation) =>
          automation.id === id ? { ...automation, enabled } : automation,
        ),
      );
      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) return;
      void bridge.setScheduleEnabled({ id, enabled }).then(() => hydrateHermsecState());
    },
    [hydrateHermsecState],
  );

  const handleRunAutomation = useCallback(
    async (id: string) => {
      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) return;
      setAutomations((current) =>
        current.map((automation) =>
          automation.id === id ? { ...automation, lastResult: "running" } : automation,
        ),
      );
      setAgentStatus("Running automation");
      try {
        const result = await bridge.runSchedule({ id, force: true });
        appendAssistant(result.parsed?.message ?? "Automation run completed.");
        updateProjectFromScan(result);
        await hydrateHermsecState();
        if (result.ok) {
          await openLatestReport();
        }
      } catch (error) {
        appendAssistant(error instanceof Error ? error.message : "Automation run failed.");
      } finally {
        setAgentStatus("Agent ready");
      }
    },
    [appendAssistant, hydrateHermsecState, openLatestReport, updateProjectFromScan],
  );

  const handleDeleteAutomation = useCallback(
    async (id: string) => {
      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) {
        setAutomations((current) => current.filter((automation) => automation.id !== id));
        return;
      }
      const confirmed = await window.desktopBridge?.confirm?.("Delete this Hermsec automation?");
      if (confirmed === false) return;
      await bridge.removeSchedule({ id });
      await hydrateHermsecState();
    },
    [hydrateHermsecState],
  );

  const handleEditAutomation = useCallback(
    async (id: string) => {
      const bridge = window.desktopBridge?.hermsec;
      if (!bridge) return;
      const result = await bridge.updateSchedule({
        id,
        dailyTime: dailyTimeFromSettings(settings.automationDefaultSchedule),
        mode: settings.scanMode,
      });
      appendAssistant(result.parsed?.message ?? "Automation updated.");
      await hydrateHermsecState();
    },
    [appendAssistant, hydrateHermsecState, settings.automationDefaultSchedule, settings.scanMode],
  );

  const handleSettingsChange = useCallback(
    (patch: Partial<HermsecSettingsState>) => {
      setSettings((current) => {
        const { apiKeyValue, ...persistedPatch } = patch;
        const next = { ...current, ...persistedPatch };
        const bridge = window.desktopBridge?.hermsec;
        if (bridge) {
          void bridge
            .saveSettings({
              provider: next.provider,
              model: next.model,
              apiKeyEnvVar: next.apiKeyEnvVar,
              ...(apiKeyValue ? { apiKeyValue } : {}),
              baseUrl: next.baseUrl,
              defaultReportDirectory: next.defaultReportDirectory,
              privacyMode: next.privacyMode,
            })
            .then(() => hydrateHermsecState());
        }
        return next;
      });
    },
    [hydrateHermsecState],
  );

  return (
    <div
      className="flex h-svh min-h-0 flex-col bg-background text-foreground"
      data-hermsec-desktop
    >
      <SidebarProvider
        defaultOpen
        className="min-h-0 flex-1 bg-background"
        data-sidebar-side="left"
      >
        <Sidebar
          side="left"
          collapsible="offcanvas"
          className={cn("text-foreground", SIDEBAR_OFFCANVAS_MOTION_CLASS)}
          gapClassName={cn(SIDEBAR_GAP_CLASS, SIDEBAR_OFFCANVAS_MOTION_CLASS)}
          innerClassName={SIDEBAR_INNER_CLASS}
          transparentSurface
          resizable={LEFT_SIDEBAR_RESIZABLE}
        >
          <HermsecLeftSidebar
            activeView={activeView}
            onSelectView={setActiveView}
            onNewChat={handleNewChat}
          />
        </Sidebar>

        <div className="relative flex min-h-0 min-w-0 flex-1">
          <SidebarInstanceProvider side="left" resizable={LEFT_SIDEBAR_RESIZABLE}>
            <SidebarRail placement="content-seam" />
          </SidebarInstanceProvider>

          <HermsecMainSurface
            activeView={activeView}
            messages={messages}
            automations={bridgeReady ? automations : MOCK_AUTOMATIONS}
            projects={projects}
            settings={settings}
            activeProjectId={activeProject?.id}
            onToggleAutomation={handleToggleAutomation}
            onRunAutomation={handleRunAutomation}
            onDeleteAutomation={handleDeleteAutomation}
            onCreateAutomation={createAutomation}
            onEditAutomation={handleEditAutomation}
            onSettingsChange={handleSettingsChange}
            onSelectProject={setActiveProjectId}
            onSendMessage={handleSendMessage}
            onChoice={handleChoice}
            onQuickAction={handleQuickAction}
            onOpenReport={handleOpenReport}
          />

          <HermsecRightPanel
            open={rightPanelOpen}
            preview={reportPreview}
            onOpenChange={setRightPanelOpen}
            onClosePreview={() => {
              setReportPreview(null);
              setRightPanelOpen(false);
            }}
          />
        </div>
      </SidebarProvider>

      <HermsecStatusBar
        projectName={activeProject?.name}
        projectPath={activeProject?.path}
        scanMode={settings.scanMode}
        agentStatus={agentStatus}
      />
    </div>
  );
}
