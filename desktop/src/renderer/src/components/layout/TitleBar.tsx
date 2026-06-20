import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  ChevronRight,
  Clock,
  Database,
  FileText,
  FolderOpen,
  Minus,
  ScanLine,
  Shield,
  Square,
  X,
} from "lucide-react";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import { useReportStore } from "@/store/reportStore";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { HermsecLogo } from "@/components/branding/HermsecLogo";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";

type MenuName = "File" | "Edit" | "View" | "Window" | "Help";

type MenuEntry =
  | { type: "separator" }
  | {
      type: "item";
      label: string;
      shortcut?: string;
      disabled?: boolean;
      action: () => void;
    };

const menuNames: MenuName[] = ["File", "Edit", "View", "Window", "Help"];

export function TitleBar() {
  const api = getHermsecApi();
  const menuRef = useRef<HTMLDivElement>(null);
  const [openMenu, setOpenMenu] = useState<MenuName | null>(null);
  const [aboutOpen, setAboutOpen] = useState(false);
  const setView = useUiStore((s) => s.setView);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const startNewSession = useSessionStore((s) => s.startNewSession);
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const latestReport = useReportStore((s) => s.latestReport);
  const loadDashboard = useReportStore((s) => s.loadDashboard);

  useEffect(() => {
    const handlePointerDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) {
        setOpenMenu(null);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpenMenu(null);
        setAboutOpen(false);
      }
    };
    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  const openFolder = async () => {
    const directory = await requireHermsecApi().settings.chooseProjectDirectory(settings?.defaultProjectDir);
    if (!directory) return;
    await updateSettings({ defaultProjectDir: directory });
    startNewSession();
    setView("chat");
  };

  const openDashboard = () => {
    setView("dashboard");
    if (latestReport?.reportDir) {
      void loadDashboard(latestReport.reportDir);
    }
  };

  const menuItems = useMemo<Record<MenuName, MenuEntry[]>>(
    () => ({
      File: [
        { type: "item", label: "Close", shortcut: "Ctrl+W", action: () => void api?.window.close() },
        { type: "item", label: "New Window", shortcut: "Ctrl+Shift+N", action: () => void api?.window.new() },
        {
          type: "item",
          label: "New Chat",
          shortcut: "Ctrl+N",
          action: () => {
            startNewSession();
            setView("chat");
          },
        },
        { type: "item", label: "Open Folder...", shortcut: "Ctrl+O", action: () => void openFolder() },
        { type: "separator" },
        { type: "item", label: "Settings...", shortcut: "Ctrl+Comma", action: () => setView("settings") },
        { type: "separator" },
        { type: "item", label: "Exit", action: () => void api?.window.close() },
      ],
      Edit: [
        { type: "item", label: "Undo", shortcut: "Ctrl+Z", action: () => runEditCommand("undo") },
        { type: "item", label: "Redo", shortcut: "Ctrl+Y", action: () => runEditCommand("redo") },
        { type: "separator" },
        { type: "item", label: "Cut", shortcut: "Ctrl+X", action: () => runEditCommand("cut") },
        { type: "item", label: "Copy", shortcut: "Ctrl+C", action: () => runEditCommand("copy") },
        { type: "item", label: "Paste", shortcut: "Ctrl+V", action: () => runEditCommand("paste") },
        { type: "item", label: "Delete", action: () => runEditCommand("delete") },
        { type: "separator" },
        { type: "item", label: "Select All", shortcut: "Ctrl+A", action: () => runEditCommand("selectAll") },
      ],
      View: [
        { type: "item", label: "Toggle Sidebar", shortcut: "Ctrl+B", action: toggleSidebar },
        { type: "item", label: "Toggle Bottom Panel", shortcut: "Ctrl+J", action: toggleSidebar },
        { type: "item", label: "Open Dashboard", action: openDashboard },
        { type: "item", label: "Reload Browser Page", shortcut: "Ctrl+R", action: () => window.location.reload() },
        { type: "item", label: "Toggle Side Panel", shortcut: "Alt+Ctrl+B", action: toggleSidebar },
        { type: "item", label: "Find", shortcut: "Ctrl+F", action: () => setView("chat") },
        { type: "separator" },
        { type: "item", label: "Previous Chat", shortcut: "Ctrl+Shift+[", action: () => setView("chat") },
        { type: "item", label: "Next Chat", shortcut: "Ctrl+Shift+]", action: () => setView("chat") },
        { type: "item", label: "Back", shortcut: "Ctrl+[", action: () => window.history.back() },
        { type: "item", label: "Forward", shortcut: "Ctrl+]", action: () => window.history.forward() },
        { type: "separator" },
        { type: "item", label: "Zoom In", shortcut: "Ctrl+Shift+=", action: () => void api?.window.zoomIn() },
        { type: "item", label: "Zoom Out", shortcut: "Ctrl+-", action: () => void api?.window.zoomOut() },
        { type: "item", label: "Actual Size", shortcut: "Ctrl+0", action: () => void api?.window.actualSize() },
        { type: "separator" },
        { type: "item", label: "Toggle Full Screen", shortcut: "F11", action: () => void api?.window.toggleFullscreen() },
      ],
      Window: [
        { type: "item", label: "Minimize", shortcut: "Ctrl+M", action: () => void api?.window.minimize() },
        { type: "item", label: "Zoom", action: () => void api?.window.maximize() },
        { type: "item", label: "Close", shortcut: "Ctrl+W", action: () => void api?.window.close() },
      ],
      Help: [
        { type: "item", label: "About", action: () => setAboutOpen(true) },
      ],
    }),
    [api, latestReport?.reportDir, loadDashboard, setView, startNewSession, toggleSidebar, updateSettings, settings?.defaultProjectDir],
  );

  return (
    <header className="drag-region relative flex h-9 shrink-0 items-center justify-between border-b border-border-subtle bg-background px-3">
      <div className="flex items-center gap-4">
        <div className="no-drag flex items-center gap-2">
          <HermsecLogo className="h-4 w-4 text-accent" aria-label="Hermsec" />
          <span className="text-xs font-medium tracking-wide text-muted">Hermsec</span>
        </div>
        <nav ref={menuRef} className="no-drag flex items-center gap-1">
          {menuNames.map((name) => (
            <div key={name} className="relative">
              <button
                type="button"
                className={cn(
                  "rounded-md px-2 py-1 text-xs text-muted transition-colors duration-150 ease-out hover:bg-white/7 hover:text-foreground active:scale-[0.98]",
                  openMenu === name && "bg-white/9 text-foreground",
                )}
                onClick={() => setOpenMenu((current) => (current === name ? null : name))}
              >
                {name}
              </button>
              {openMenu === name ? (
                <MenuSurface
                  entries={menuItems[name]}
                  onClose={() => setOpenMenu(null)}
                  align={name === "Window" ? "center" : "left"}
                />
              ) : null}
            </div>
          ))}
        </nav>
      </div>
      <div className="no-drag flex items-center">
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
      <AboutHermsecModal open={aboutOpen} onClose={() => setAboutOpen(false)} />
    </header>
  );
}

function MenuSurface({
  entries,
  onClose,
  align = "left",
}: {
  entries: MenuEntry[];
  onClose: () => void;
  align?: "left" | "center";
}) {
  return (
    <div
      className={cn(
        "absolute top-7 z-50 w-[236px] overflow-hidden rounded-lg border border-border bg-[#1e1e1f] py-1 shadow-[0_18px_55px_rgba(0,0,0,0.5)]",
        align === "center" ? "left-1/2 -translate-x-1/2" : "left-0",
      )}
    >
      {entries.map((entry, index) =>
        entry.type === "separator" ? (
          <div key={`separator-${index}`} className="my-1 h-px bg-border" />
        ) : (
          <button
            key={`${entry.label}-${index}`}
            type="button"
            disabled={entry.disabled}
            className="flex h-8 w-full items-center justify-between gap-3 px-3 text-left text-xs text-foreground transition-colors duration-100 ease-out hover:bg-white/8 active:bg-white/10 disabled:pointer-events-none disabled:opacity-40"
            onClick={() => {
              entry.action();
              onClose();
            }}
          >
            <span className="truncate">{entry.label}</span>
            {entry.shortcut ? <span className="shrink-0 text-[11px] text-muted">{entry.shortcut}</span> : null}
          </button>
        ),
      )}
    </div>
  );
}

function AboutHermsecModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="About Hermsec"
      className="w-[min(680px,calc(100vw-48px))] max-h-[calc(100vh-96px)] overflow-hidden rounded-2xl bg-surface-elevated"
      bodyClassName="overflow-y-auto pr-2 pb-1"
    >
      <div className="mb-5 rounded-2xl border border-border bg-background/70 p-4">
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-border bg-background shadow-[0_14px_40px_rgba(0,0,0,0.28)]">
            <HermsecLogo className="h-8 w-8 text-accent" aria-label="Hermsec" />
          </div>
          <div>
            <h3 className="text-xl font-semibold tracking-tight text-foreground">Hermsec</h3>
            <p className="mt-1 text-sm text-muted">
              A security IDE for local projects, built around scanner evidence and a bounded assistant.
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-5">
        <AboutSection
          icon={<Shield className="h-4 w-4" />}
          title="What Hermsec Is"
          body="Hermsec helps developers inspect local repositories for security incidents before they ship. It is designed for project security conversations: scan a codebase, review evidence, understand priority, generate reports, and plan fixes without turning the assistant into an unrestricted coding agent."
        />
        <AboutSection
          icon={<ScanLine className="h-4 w-4" />}
          title="How Scans Work"
          body="The scan starts with concrete tooling evidence, then turns that evidence into local reports. Hermsec keeps raw scanner findings visible so the model can explain and prioritize, but not erase or invent evidence."
        />
        <FeatureGrid
          items={[
            ["Hermsec heuristics", "Local pattern checks for secrets, risky execution, package/config risks, and common insecure code paths."],
            ["Semgrep", "Static analysis rules for JavaScript, TypeScript, Python, and framework-level vulnerability patterns."],
            ["Gitleaks", "Secret detection for tokens, keys, and credential-like values committed to source."],
            ["Bandit", "Python security checks for unsafe subprocesses, eval usage, weak crypto, and more."],
            ["OSV and pip-audit", "Dependency vulnerability checks against advisory databases for npm and Python ecosystems."],
            ["SafeDep PMG", "Package-manager safety wrapper and npm audit support for supply-chain hygiene."],
          ]}
        />
        <AboutSection
          icon={<Bot className="h-4 w-4" />}
          title="Agent Behavior"
          body="The assistant is scoped to defensive security work. It can explain findings, show affected files and lines, walk through remediation, create a prompt for another coding agent, and answer follow-up questions from the latest report. If a provider is configured, it uses your selected model with a compact redacted evidence packet."
        />
        <div className="grid gap-3 sm:grid-cols-2">
          <MiniCard
            icon={<FileText className="h-4 w-4" />}
            title="Reports"
            text="Hermsec writes HTML, JSON, an interactive dashboard, a one-page executive report, and a PDF artifact into your configured report folder."
          />
          <MiniCard
            icon={<Clock className="h-4 w-4" />}
            title="Automations"
            text="In-app automations run only while Hermsec is open. They check project changes first, then scan only when a rerun is useful."
          />
          <MiniCard
            icon={<Database className="h-4 w-4" />}
            title="Local State"
            text="Settings, sessions, report metadata, project fingerprints, and automation state are stored locally on your PC."
          />
          <MiniCard
            icon={<Activity className="h-4 w-4" />}
            title="Online MVP"
            text="V3 is online-scan-only: scanner evidence, dependency intelligence, report generation, and optional model explanation run as one pipeline."
          />
        </div>
        <div className="rounded-2xl border border-border bg-background/70 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-medium text-foreground">
            <CheckCircle2 className="h-4 w-4 text-success" />
            Current MVP Features
          </div>
          <div className="grid gap-2 text-xs leading-relaxed text-muted sm:grid-cols-2">
            {[
              "Project-scoped persistent chats",
              "Scanner progress with stage status",
              "Stop and restart running scans",
              "Interactive dashboard view",
              "Chat-driven automation setup",
              "Configurable report directory",
              "Provider and model settings",
              "Copy-ready fix prompts",
            ].map((item) => (
              <div key={item} className="flex items-center gap-2">
                <ChevronRight className="h-3 w-3 text-accent" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function AboutSection({
  icon,
  title,
  body,
}: {
  icon: ReactNode;
  title: string;
  body: string;
}) {
  return (
    <section className="rounded-2xl border border-border bg-background/70 p-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium text-foreground">
        <span className="text-accent">{icon}</span>
        {title}
      </div>
      <p className="text-sm leading-relaxed text-muted">{body}</p>
    </section>
  );
}

function FeatureGrid({ items }: { items: Array<[string, string]> }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {items.map(([title, text]) => (
        <MiniCard key={title} icon={<FolderOpen className="h-4 w-4" />} title={title} text={text} />
      ))}
    </div>
  );
}

function MiniCard({
  icon,
  title,
  text,
}: {
  icon: ReactNode;
  title: string;
  text: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-background/55 p-3 transition-colors duration-150 ease-out hover:bg-background/80">
      <div className="mb-1.5 flex items-center gap-2 text-xs font-semibold text-foreground">
        <span className="text-accent">{icon}</span>
        {title}
      </div>
      <p className="text-xs leading-relaxed text-muted">{text}</p>
    </div>
  );
}

function runEditCommand(command: string): void {
  document.execCommand(command);
}
