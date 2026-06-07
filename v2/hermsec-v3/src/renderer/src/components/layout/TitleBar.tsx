import { Clock, LayoutDashboard, Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";
import { getHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import { useReportStore } from "@/store/reportStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { AutomationPopover } from "@/components/automation/AutomationPopover";
import { HermsecLogo } from "@/components/branding/HermsecLogo";
import { Button } from "@/components/ui/Button";

const menuItems = ["File", "Edit", "View", "Help"];

export function TitleBar() {
  const api = getHermsecApi();
  const [automationOpen, setAutomationOpen] = useState(false);
  const settings = useSettingsStore((s) => s.settings);
  const view = useUiStore((s) => s.view);
  const setView = useUiStore((s) => s.setView);
  const latestReport = useReportStore((s) => s.latestReport);
  const hydrateLatest = useReportStore((s) => s.hydrateLatest);

  useEffect(() => {
    if (!settings?.defaultProjectDir) return;
    void hydrateLatest(settings.defaultProjectDir);
  }, [hydrateLatest, settings?.defaultProjectDir]);

  return (
    <header className="drag-region relative flex h-9 shrink-0 items-center justify-between border-b border-border-subtle bg-background px-3">
      <div className="flex items-center gap-4">
        <div className="no-drag flex items-center gap-2">
          <HermsecLogo className="h-4 w-4 text-accent" aria-label="Hermsec" />
          <span className="text-xs font-medium tracking-wide text-muted">Hermsec</span>
        </div>
        <nav className="no-drag flex items-center gap-3">
          {menuItems.map((item) => (
            <button
              key={item}
              type="button"
              className="text-xs text-muted transition-colors hover:text-foreground"
            >
              {item}
            </button>
          ))}
        </nav>
      </div>
      <div className="no-drag flex items-center gap-1">
        <Button
          variant={view === "dashboard" ? "subtle" : "ghost"}
          size="icon"
          title={latestReport?.dashboardHtmlPath ? "Open dashboard" : "Run a scan to enable dashboard"}
          disabled={!latestReport?.dashboardHtmlPath}
          onClick={() => setView("dashboard")}
        >
          <LayoutDashboard className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant={automationOpen ? "subtle" : "ghost"}
          size="icon"
          title="Automation"
          onClick={() => setAutomationOpen((open) => !open)}
        >
          <Clock className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          onClick={() => api && void api.window.minimize()}
        >
          <Minus className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          onClick={() => api && void api.window.maximize()}
        >
          <Square className="h-3 w-3" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          className={cn(!api && "opacity-30")}
          onClick={() => api && void api.window.close()}
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
      <AutomationPopover open={automationOpen} onClose={() => setAutomationOpen(false)} />
    </header>
  );
}
