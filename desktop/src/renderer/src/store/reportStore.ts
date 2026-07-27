import { create } from "zustand";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import type { LatestReportResult } from "@/types/reports";
import type { ScanProgressEvent, ScanProjectRequest, ScanProjectResult } from "@/types/scan";
import { shouldAcceptRunEvent, shouldApplyRunCompletion } from "../../../shared/scanRunIsolation";

interface ReportState {
  latestReport: LatestReportResult | null;
  dashboardHtml: string | null;
  progress: ScanProgressEvent[];
  scanRunning: boolean;
  activeRunId: string | null;
  terminalRunId: string | null;
  toast: string | null;
  lastScanRequest: ScanProjectRequest | null;
  restartAfterCancel: boolean;
  subscribeToProgress: () => void;
  hydrateLatest: (projectPath?: string) => Promise<LatestReportResult | null>;
  loadDashboard: (reportDir?: string) => Promise<string | null>;
  runScan: (request: ScanProjectRequest) => Promise<ScanProjectResult>;
  cancelScan: () => Promise<void>;
  restartScan: (request?: ScanProjectRequest) => Promise<void>;
  setToast: (message: string | null) => void;
  clearProgress: () => void;
}

let unsubscribeProgress: (() => void) | null = null;

export const useReportStore = create<ReportState>((set, get) => ({
  latestReport: null,
  dashboardHtml: null,
  progress: [],
  scanRunning: false,
  activeRunId: null,
  terminalRunId: null,
  toast: null,
  lastScanRequest: null,
  restartAfterCancel: false,

  subscribeToProgress: () => {
    if (unsubscribeProgress) return;
    const api = getHermsecApi();
    if (!api) return;
    unsubscribeProgress = api.scan.onProgress((event) => {
      set((state) => {
        if (!shouldAcceptRunEvent(state.activeRunId, state.terminalRunId, event.runId)) {
          return state;
        }
        return {
          progress: upsertProgress(state.progress, event),
          ...(event.terminalStatus ? { terminalRunId: event.runId } : {}),
        };
      });
    });
  },

  hydrateLatest: async (projectPath) => {
    const api = getHermsecApi();
    if (!api) return null;
    const latest = await api.reports.latest(projectPath);
    const next = latest.ok ? latest : null;
    set({ latestReport: next, ...(next ? {} : { dashboardHtml: null }) });
    return next;
  },

  loadDashboard: async (reportDir) => {
    const source = reportDir ?? get().latestReport?.reportDir;
    if (!source) return null;
    try {
      const result = await requireHermsecApi().reports.dashboardBundle({ reportPathOrDir: source });
      if (!result.ok || !result.html) {
        set({ dashboardHtml: null, toast: result.message ?? "Dashboard is not available yet." });
        return null;
      }
      set({ dashboardHtml: result.html });
      return result.html;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Dashboard is not available yet.";
      set({ dashboardHtml: null, toast: message });
      return null;
    }
  },

  runScan: async (request) => {
    const currentRunId = get().activeRunId;
    if (currentRunId) {
      return {
        ok: false,
        message: "A scan is already running. Stop or restart it before starting another scan.",
        error: "scan-already-running",
        runId: currentRunId,
      };
    }
    const runId = createRunId();
    const requestForRun = { ...request, runId };
    set({
      scanRunning: true,
      progress: [],
      toast: null,
      activeRunId: runId,
      terminalRunId: null,
      lastScanRequest: { ...request, runId: undefined },
    });
    try {
      const result = await requireHermsecApi().scan.project(requestForRun);
      if (!shouldApplyRunCompletion(get().activeRunId, runId)) {
        return result;
      }
      if (result.ok && !result.unchanged) {
        const latest: LatestReportResult = {
          ok: true,
          projectPath: result.targetPath,
          reportDir: result.reportDir,
          htmlPath: result.htmlPath,
          dashboardHtmlPath: result.dashboardHtmlPath,
          onepagerHtmlPath: result.onepagerHtmlPath,
          onepagerPdfPath: result.onepagerPdfPath,
          runId: result.runId ?? runId,
          assistMode: result.assistMode,
          assistModeLabel: result.assistModeLabel,
          terminalStatus: result.terminalStatus,
          degradationReasons: result.degradationReasons,
          projectState: result.projectState,
        };
        set({ latestReport: latest });
        if (result.reportDir) {
          await get().loadDashboard(result.reportDir);
        }
      }
      if (result.unchanged) {
        set({ toast: "No project changes since the last scan." });
      }
      if (result.canceled) {
        set({ toast: "Scan stopped." });
      }
      set({ terminalRunId: result.runId ?? runId });
      return result;
    } finally {
      const isCurrentRun = shouldApplyRunCompletion(get().activeRunId, runId);
      const restartRequest = isCurrentRun && get().restartAfterCancel ? get().lastScanRequest : null;
      if (isCurrentRun) {
        set({ scanRunning: false, activeRunId: null, restartAfterCancel: false });
      }
      if (restartRequest) {
        window.setTimeout(() => {
          void get().runScan(restartRequest);
        }, 120);
      }
    }
  },

  cancelScan: async () => {
    const activeRunId = get().activeRunId;
    if (!activeRunId) {
      set({ toast: "No scan is currently running." });
      return;
    }
    const result = await requireHermsecApi().scan.cancel(activeRunId);
    set({ toast: result.message });
  },

  restartScan: async (request) => {
    const currentRequest = request ?? get().lastScanRequest;
    if (!currentRequest) {
      set({ toast: "No scan request is available to restart." });
      return;
    }
    if (get().scanRunning) {
      set({ restartAfterCancel: true, lastScanRequest: currentRequest, toast: "Restarting scan..." });
      const activeRunId = get().activeRunId;
      if (activeRunId) {
        await requireHermsecApi().scan.cancel(activeRunId);
      }
      return;
    }
    void get().runScan(currentRequest);
  },

  setToast: (toast) => set({ toast }),
  clearProgress: () => set({ progress: [] }),
}));

function upsertProgress(events: ScanProgressEvent[], next: ScanProgressEvent): ScanProgressEvent[] {
  const byId = new Map(events.map((event) => [event.id, event]));
  byId.set(next.id, next);
  return Array.from(byId.values());
}

function createRunId(): string {
  const uuid = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `renderer-${uuid}`;
}
