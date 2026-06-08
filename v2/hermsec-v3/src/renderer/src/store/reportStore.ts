import { create } from "zustand";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import type { LatestReportResult } from "@/types/reports";
import type { ScanProgressEvent, ScanProjectRequest, ScanProjectResult } from "@/types/scan";

interface ReportState {
  latestReport: LatestReportResult | null;
  dashboardHtml: string | null;
  progress: ScanProgressEvent[];
  scanRunning: boolean;
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
  toast: null,
  lastScanRequest: null,
  restartAfterCancel: false,

  subscribeToProgress: () => {
    if (unsubscribeProgress) return;
    const api = getHermsecApi();
    if (!api) return;
    unsubscribeProgress = api.scan.onProgress((event) => {
      set((state) => ({
        progress: upsertProgress(state.progress, event),
      }));
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
    const result = await requireHermsecApi().reports.dashboardBundle({ reportPathOrDir: source });
    if (!result.ok || !result.html) {
      set({ dashboardHtml: null, toast: result.message ?? "Dashboard is not available yet." });
      return null;
    }
    set({ dashboardHtml: result.html });
    return result.html;
  },

  runScan: async (request) => {
    set({ scanRunning: true, progress: [], toast: null, lastScanRequest: request });
    try {
      const result = await requireHermsecApi().scan.project(request);
      if (result.ok && !result.unchanged) {
        const latest: LatestReportResult = {
          ok: true,
          projectPath: result.targetPath,
          reportDir: result.reportDir,
          htmlPath: result.htmlPath,
          dashboardHtmlPath: result.dashboardHtmlPath,
          onepagerHtmlPath: result.onepagerHtmlPath,
          onepagerPdfPath: result.onepagerPdfPath,
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
      return result;
    } finally {
      const restartRequest = get().restartAfterCancel ? get().lastScanRequest : null;
      set({ scanRunning: false, restartAfterCancel: false });
      if (restartRequest) {
        window.setTimeout(() => {
          void get().runScan(restartRequest);
        }, 120);
      }
    }
  },

  cancelScan: async () => {
    const result = await requireHermsecApi().scan.cancel();
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
      await requireHermsecApi().scan.cancel();
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
