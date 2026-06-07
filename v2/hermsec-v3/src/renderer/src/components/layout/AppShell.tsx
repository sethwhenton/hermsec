import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef } from "react";
import { useReportStore } from "@/store/reportStore";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ChatView } from "@/components/chat/ChatView";
import { DashboardView } from "@/components/dashboard/DashboardView";
import { SettingsPanel } from "@/components/settings/SettingsPanel";
import { LeftSidebar } from "./LeftSidebar";
import { TitleBar } from "./TitleBar";

export function AppShell() {
  const view = useUiStore((s) => s.view);
  const hydrate = useSettingsStore((s) => s.hydrate);
  const settings = useSettingsStore((s) => s.settings);
  const settingsHydrated = useSettingsStore((s) => s.hydrated);
  const updateSettings = useSettingsStore((s) => s.update);
  const refreshSessions = useSessionStore((s) => s.refreshSessions);
  const openSession = useSessionStore((s) => s.openSession);
  const subscribeToProgress = useReportStore((s) => s.subscribeToProgress);
  const hydrateLatest = useReportStore((s) => s.hydrateLatest);
  const runScan = useReportStore((s) => s.runScan);
  const restoredInitialSession = useRef(false);
  const automationRunning = useRef(false);

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  useEffect(() => {
    subscribeToProgress();
  }, [subscribeToProgress]);

  useEffect(() => {
    if (restoredInitialSession.current || !settingsHydrated || !settings?.defaultProjectDir) return;
    restoredInitialSession.current = true;

    void refreshSessions().then((sessions) => {
      const latestSession = sessions.find(
        (session) => normalizePath(session.projectPath) === normalizePath(settings.defaultProjectDir),
      );
      if (latestSession) {
        void openSession(latestSession.id);
      }
    });
  }, [openSession, refreshSessions, settings?.defaultProjectDir, settingsHydrated]);

  useEffect(() => {
    if (!settingsHydrated || !settings?.automation.enabled || !settings.defaultProjectDir) return;

    const checkAutomation = async () => {
      if (automationRunning.current) return;
      if (!shouldRunAutomation(settings.automation.lastRunAt, settings.automation.frequency, settings.automation.time)) {
        return;
      }

      automationRunning.current = true;
      try {
        const latest = await hydrateLatest(settings.defaultProjectDir);
        const result = await runScan({
          targetPath: settings.defaultProjectDir,
          reportDir: settings.defaultReportDir,
          mode: "online",
          useModel: true,
          skipIfUnchanged: true,
          previousProjectState: latest?.projectState,
        });
        const now = new Date().toISOString();
        await updateSettings({
          automation: {
            ...settings.automation,
            lastCheckedAt: now,
            lastRunAt: now,
            lastResult: result.unchanged ? "No project changes since the last scan." : result.message,
            ...(result.projectState?.fingerprint
              ? { lastProjectStateFingerprint: result.projectState.fingerprint }
              : {}),
            ...(result.reportDir ? { lastReportDir: result.reportDir } : {}),
          },
        });
      } finally {
        automationRunning.current = false;
      }
    };

    void checkAutomation();
    const timer = window.setInterval(() => {
      void checkAutomation();
    }, 60_000);
    return () => window.clearInterval(timer);
  }, [
    hydrateLatest,
    runScan,
    settings,
    settingsHydrated,
    updateSettings,
  ]);

  return (
    <div className="flex h-full flex-col bg-background">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <LeftSidebar />
        <main className="relative min-w-0 flex-1">
          <AnimatePresence mode="wait">
            {view === "chat" ? (
              <motion.div
                key="chat"
                className="absolute inset-0"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.18 }}
              >
                <ChatView />
              </motion.div>
            ) : view === "dashboard" ? (
              <motion.div
                key="dashboard"
                className="absolute inset-0"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.18 }}
              >
                <DashboardView />
              </motion.div>
            ) : (
              <motion.div
                key="settings"
                className="absolute inset-0"
                initial={{ opacity: 0, scale: 0.99 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.99 }}
                transition={{ duration: 0.2 }}
              >
                <SettingsPanel />
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function shouldRunAutomation(
  lastRunAt: string | undefined,
  frequency: "daily" | "every-3-days" | "weekly",
  time: string,
): boolean {
  const now = new Date();
  const [hours, minutes] = time.split(":").map((part) => Number(part));
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return false;

  const intervalDays = frequency === "weekly" ? 7 : frequency === "every-3-days" ? 3 : 1;
  const scheduled = new Date(now);
  scheduled.setHours(hours, minutes, 0, 0);

  if (!lastRunAt) {
    return now >= scheduled;
  }

  const lastRun = new Date(lastRunAt);
  const next = new Date(lastRun);
  next.setDate(next.getDate() + intervalDays);
  next.setHours(hours, minutes, 0, 0);
  return now >= next;
}
