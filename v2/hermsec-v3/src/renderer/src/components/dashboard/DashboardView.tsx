import { AnimatePresence, motion } from "framer-motion";
import { ArrowLeft, FolderOpen, RefreshCw, RotateCw, Square } from "lucide-react";
import { useEffect } from "react";
import { requireHermsecApi } from "@/lib/ipc";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { Button } from "@/components/ui/Button";
import { ScanProgressPanel } from "@/components/scan/ScanProgressPanel";

export function DashboardView() {
  const setView = useUiStore((s) => s.setView);
  const settings = useSettingsStore((s) => s.settings);
  const latestReport = useReportStore((s) => s.latestReport);
  const dashboardHtml = useReportStore((s) => s.dashboardHtml);
  const hydrateLatest = useReportStore((s) => s.hydrateLatest);
  const loadDashboard = useReportStore((s) => s.loadDashboard);
  const runScan = useReportStore((s) => s.runScan);
  const cancelScan = useReportStore((s) => s.cancelScan);
  const restartScan = useReportStore((s) => s.restartScan);
  const scanRunning = useReportStore((s) => s.scanRunning);
  const progress = useReportStore((s) => s.progress);
  const toast = useReportStore((s) => s.toast);
  const setToast = useReportStore((s) => s.setToast);

  useEffect(() => {
    if (!settings?.defaultProjectDir) return;
    void hydrateLatest(settings.defaultProjectDir).then((latest) => {
      if (latest?.reportDir) void loadDashboard(latest.reportDir);
    });
  }, [hydrateLatest, loadDashboard, settings?.defaultProjectDir]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3500);
    return () => window.clearTimeout(timer);
  }, [setToast, toast]);

  const handleScanAgain = async () => {
    const result = await runScan({
      targetPath: settings?.defaultProjectDir,
      reportDir: settings?.defaultReportDir,
      mode: "online",
      assistMode: settings?.general.scanMode,
      useModel: true,
      skipIfUnchanged: true,
      previousProjectState: latestReport?.projectState,
    });
    if (!result.ok) {
      setToast(`Scan failed. ${result.message}`);
      return;
    }
    if (!result.unchanged) {
      setToast("Dashboard updated with the latest scan.");
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border-subtle px-4">
        <Button variant="ghost" size="sm" onClick={() => setView("chat")}>
          <ArrowLeft className="h-3.5 w-3.5" />
          Chat mode
        </Button>
        <div className="flex min-w-0 items-center gap-2 text-xs text-muted">
          <span className="truncate">{latestReport?.reportDir ?? "No report loaded"}</span>
        </div>
        <div className="flex items-center gap-2">
          {latestReport?.onepagerPdfPath ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void requireHermsecApi().reports.openArtifact({ path: latestReport.onepagerPdfPath ?? "" });
              }}
            >
              <FolderOpen className="h-3.5 w-3.5" />
              PDF
            </Button>
          ) : null}
          <Button
            variant="default"
            size="sm"
            disabled={scanRunning || !latestReport}
            onClick={() => {
              void handleScanAgain();
            }}
          >
            <RefreshCw className={scanRunning ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"} />
            Scan again
          </Button>
          {scanRunning ? (
            <>
              <Button
                variant="outline"
                size="icon"
                title="Stop scan"
                onClick={() => {
                  void cancelScan();
                }}
              >
                <Square className="h-3.5 w-3.5 fill-current" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                title="Restart scan"
                onClick={() => {
                  void restartScan();
                }}
              >
                <RotateCw className="h-3.5 w-3.5" />
              </Button>
            </>
          ) : null}
        </div>
      </div>

      <div className="relative min-h-0 flex-1">
        {dashboardHtml ? (
          <iframe
            title="Hermsec report dashboard"
            srcDoc={dashboardHtml}
            sandbox="allow-scripts allow-same-origin"
            className="h-full w-full border-0 bg-background"
          />
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="max-w-sm text-center">
              <h2 className="text-base font-medium text-foreground">No dashboard yet</h2>
              <p className="mt-2 text-sm text-muted">
                Run a project scan first. Hermsec will enable the dashboard once report artifacts are generated.
              </p>
              <Button className="mt-4" size="sm" onClick={() => setView("chat")}>
                Back to chat
              </Button>
            </div>
          </div>
        )}

        <AnimatePresence>
          {scanRunning && (
            <motion.div
              className="absolute right-4 top-4 w-[380px] max-w-[calc(100%-2rem)]"
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
              transition={{ duration: 0.18 }}
            >
              <ScanProgressPanel events={progress} compact />
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {toast && (
            <motion.div
              className="absolute bottom-4 left-1/2 max-w-md -translate-x-1/2 rounded-full border border-border bg-surface-elevated px-4 py-2 text-sm text-foreground shadow-[0_16px_50px_rgba(0,0,0,0.4)]"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              transition={{ duration: 0.18 }}
            >
              {toast}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
