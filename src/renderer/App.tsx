import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  ClipboardList,
  FolderOpen,
  Gauge,
  HardDrive,
  History,
  Loader2,
  MessageSquare,
  Radar,
  Save,
  Search,
  Settings,
  Shield,
  Sparkles,
  Terminal,
} from "lucide-react";
import type {
  ChatTurnResult,
  DesktopSettings,
  DesktopState,
  ScanWorkspaceResult,
} from "../desktop/types.js";
import type { ReportIndexEntry } from "../reports/schema.js";
import type { Finding } from "../shared/types.js";
import { parseComposerCommand, slashCommands } from "./commandLogic.js";

type Message = {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
};

type Panel = "findings" | "intel" | "reports" | "settings";

const initialMessages: Message[] = [
  {
    id: "welcome",
    role: "assistant",
    content: "Hermsec is ready. Pick a workspace, run /scan, then ask about the findings.",
  },
];

export function App() {
  const [state, setState] = useState<DesktopState | undefined>();
  const [messages, setMessages] = useState<Message[]>(initialMessages);
  const [panel, setPanel] = useState<Panel>("findings");
  const [composer, setComposer] = useState("");
  const [busy, setBusy] = useState<string | undefined>();
  const [lastScan, setLastScan] = useState<ScanWorkspaceResult | undefined>();
  const [settingsDraft, setSettingsDraft] = useState<DesktopSettings | undefined>();
  const transcriptRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (state?.settings) {
      setSettingsDraft(state.settings);
    }
  }, [state?.settings]);

  useEffect(() => {
    transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  const filteredCommands = useMemo(() => {
    const value = composer.trim().toLowerCase();
    if (!value.startsWith("/")) {
      return [];
    }
    return slashCommands.filter((item) => item.command.startsWith(value.split(/\s+/)[0] ?? value));
  }, [composer]);

  async function refresh() {
    const next = await window.hermsec.getState();
    setState(next);
  }

  async function run(label: string, action: () => Promise<void>) {
    setBusy(label);
    try {
      await action();
    } catch (error) {
      addMessage("assistant", error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(undefined);
    }
  }

  function addMessage(role: Message["role"], content: string) {
    setMessages((current) => [...current, { id: `${Date.now()}-${Math.random()}`, role, content }]);
  }

  async function pickWorkspace() {
    await run("Opening workspace", async () => {
      const workspace = await window.hermsec.pickWorkspace();
      if (workspace) {
        addMessage("assistant", `Workspace selected: ${workspace.displayName}`);
      }
      await refresh();
    });
  }

  async function scanActiveWorkspace() {
    await run("Scanning", async () => {
      const input = { mode: state?.activeWorkspace?.scanMode ?? "offline" } as Parameters<typeof window.hermsec.scanWorkspace>[0];
      if (state?.activeWorkspace?.id) {
        input.workspaceId = state.activeWorkspace.id;
      }
      const scan = await window.hermsec.scanWorkspace(input);
      setLastScan(scan);
      setPanel("findings");
      addMessage("assistant", scan.summaryText);
      await refresh();
    });
  }

  async function updateIntel() {
    await run("Updating intel", async () => {
      const result = await window.hermsec.updateIntel(false);
      setPanel("intel");
      addMessage("assistant", result.summaryText ?? result.message);
      await refresh();
    });
  }

  async function runDoctor() {
    await run("Checking tools", async () => {
      const result = await window.hermsec.runDoctor();
      addMessage("assistant", result.message);
    });
  }

  async function submitComposer() {
    const content = composer.trim();
    if (!content || busy) {
      return;
    }
    setComposer("");
    addMessage("user", content);
    const parsed = parseComposerCommand(content);
    if (parsed?.command === "settings") {
      setPanel("settings");
      addMessage("assistant", "Settings opened.");
      return;
    }
    await run("Thinking", async () => {
      const input = { content } as Parameters<typeof window.hermsec.ask>[0];
      if (state?.activeWorkspace?.id) {
        input.workspaceId = state.activeWorkspace.id;
      }
      if (state?.sessions[0]?.id) {
        input.sessionId = state.sessions[0].id;
      }
      const result = await window.hermsec.ask(input);
      handleChatResult(result);
      await refresh();
    });
  }

  function handleChatResult(result: ChatTurnResult) {
    if (result.scan) {
      setLastScan(result.scan);
      setPanel("findings");
    }
    if (result.intel) {
      setPanel("intel");
    }
    addMessage("assistant", result.message);
  }

  async function saveSettings() {
    if (!settingsDraft) {
      return;
    }
    await run("Saving settings", async () => {
      const next = await window.hermsec.saveSettings(settingsDraft);
      setState(next);
      addMessage("assistant", "Settings saved.");
    });
  }

  const activeFindings = lastScan?.run.findings ?? [];
  const activeReports = state?.reports ?? [];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <HermsecMark />
          <div>
            <div className="brand-title">Hermsec</div>
            <div className="brand-subtitle">security agent</div>
          </div>
        </div>
        <button className="workspace-picker" type="button" onClick={pickWorkspace}>
          <FolderOpen size={16} />
          <span>{state?.activeWorkspace?.displayName ?? "Choose workspace"}</span>
        </button>
        <nav className="nav-stack">
          <NavButton active={panel === "findings"} icon={<Shield size={15} />} label="Investigation" onClick={() => setPanel("findings")} />
          <NavButton active={panel === "intel"} icon={<Radar size={15} />} label="Intel" onClick={() => setPanel("intel")} />
          <NavButton active={panel === "reports"} icon={<ClipboardList size={15} />} label="Reports" onClick={() => setPanel("reports")} />
          <NavButton active={panel === "settings"} icon={<Settings size={15} />} label="Settings" onClick={() => setPanel("settings")} />
        </nav>
        <div className="sidebar-section">
          <div className="section-label">Recent</div>
          {(state?.workspaces ?? []).slice(0, 6).map((workspace) => (
            <button
              className={`sidebar-row ${workspace.id === state?.activeWorkspace?.id ? "active" : ""}`}
              key={workspace.id}
              type="button"
              onClick={() => {
                void run("Switching workspace", async () => {
                  await window.hermsec.setActiveWorkspace(workspace.id);
                  await refresh();
                });
              }}
            >
              <HardDrive size={14} />
              <span>{workspace.displayName}</span>
            </button>
          ))}
        </div>
        <div className="sidebar-footer">
          <StatusPill
            label={state?.providerHealth.provider ?? "none"}
            tone={state?.providerHealth.ok ? "good" : "warn"}
          />
          <StatusPill label={state?.settings.privacyMode ?? "local-only"} tone="neutral" />
        </div>
      </aside>

      <main className="main-surface">
        <header className="topbar">
          <div>
            <div className="eyebrow">Hermsec workspace</div>
            <h1>{state?.activeWorkspace?.displayName ?? "Local security desk"}</h1>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" type="button" title="Doctor" onClick={runDoctor}>
              <Gauge size={17} />
            </button>
            <button className="action-button" type="button" onClick={updateIntel}>
              <Radar size={16} />
              Intel
            </button>
            <button className="primary-button" type="button" onClick={scanActiveWorkspace} disabled={!state?.activeWorkspace || Boolean(busy)}>
              <Search size={16} />
              Scan
            </button>
          </div>
        </header>

        <section className="content-grid">
          <div className="chat-column">
            <div className="transcript" ref={transcriptRef}>
              {messages.map((message) => (
                <MessageBubble key={message.id} message={message} />
              ))}
              {busy ? (
                <div className="message assistant">
                  <Loader2 className="spin" size={15} />
                  <span>{busy}</span>
                </div>
              ) : null}
            </div>
            <div className="composer-wrap">
              {filteredCommands.length > 0 ? (
                <div className="command-palette">
                  {filteredCommands.map((item) => (
                    <button
                      key={item.command}
                      type="button"
                      onClick={() => setComposer(`${item.command} `)}
                    >
                      <span>{item.command}</span>
                      <small>{item.description}</small>
                    </button>
                  ))}
                </div>
              ) : null}
              <textarea
                value={composer}
                rows={3}
                placeholder="Ask Hermsec or type /"
                onChange={(event) => setComposer(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void submitComposer();
                  }
                }}
              />
              <div className="composer-footer">
                <span>
                  <Sparkles size={13} />
                  {state?.providerHealth.provider ?? "none"} · {state?.settings.model ?? "deepseek-v4-flash"}
                </span>
                <span>Enter sends · Shift+Enter newline</span>
              </div>
            </div>
          </div>

          <aside className="inspector">
            {panel === "findings" ? <FindingsPanel findings={activeFindings} scan={lastScan} /> : null}
            {panel === "intel" ? <IntelPanel state={state} /> : null}
            {panel === "reports" ? <ReportsPanel reports={activeReports} /> : null}
            {panel === "settings" ? (
              <SettingsPanel
                state={state}
                draft={settingsDraft}
                setDraft={setSettingsDraft}
                save={saveSettings}
              />
            ) : null}
          </aside>
        </section>
      </main>
    </div>
  );
}

function HermsecMark() {
  return (
    <div className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 64 64" role="img">
        <path d="M13 7 L26 15 V28 H38 V15 L51 7 V56 L38 47 V36 H26 V47 L13 56 Z" />
        <circle cx="32" cy="39" r="5" />
        <path d="M29 43 H35 L38 54 H26 Z" />
      </svg>
    </div>
  );
}

function NavButton(props: { active: boolean; icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button className={`nav-button ${props.active ? "active" : ""}`} type="button" onClick={props.onClick}>
      {props.icon}
      <span>{props.label}</span>
      <ChevronRight size={13} />
    </button>
  );
}

function StatusPill(props: { label: string; tone: "good" | "warn" | "neutral" }) {
  return <span className={`status-pill ${props.tone}`}>{props.label}</span>;
}

function MessageBubble({ message }: { message: Message }) {
  return (
    <div className={`message ${message.role}`}>
      {message.role === "assistant" ? <Bot size={15} /> : message.role === "user" ? <MessageSquare size={15} /> : <Terminal size={15} />}
      <pre>{message.content}</pre>
    </div>
  );
}

function FindingsPanel({ findings, scan }: { findings: Finding[]; scan: ScanWorkspaceResult | undefined }) {
  const summary = scan?.run.summary;
  return (
    <div className="panel">
      <PanelHeader icon={<Shield size={17} />} title="Investigation" subtitle={scan ? scan.run.id : "No scan yet"} />
      <div className="metric-grid">
        <Metric label="Total" value={summary?.total ?? 0} />
        <Metric label="Critical" value={summary?.critical ?? 0} tone="danger" />
        <Metric label="High" value={summary?.high ?? 0} tone="warn" />
        <Metric label="Medium" value={summary?.medium ?? 0} />
      </div>
      <div className="panel-list">
        {findings.length === 0 ? <EmptyLine text="Run a scan to populate findings." /> : null}
        {findings.slice(0, 10).map((finding) => (
          <div className="finding-row" key={finding.id}>
            <div className={`severity ${finding.severity}`}>{finding.severity}</div>
            <div>
              <strong>{finding.title}</strong>
              <p>{finding.location?.file ?? finding.package?.name ?? finding.category}</p>
            </div>
          </div>
        ))}
      </div>
      {scan?.report.htmlPath ? (
        <button className="wide-button" type="button" onClick={() => void window.hermsec.openPath(scan.report.htmlPath ?? "")}>
          <ClipboardList size={15} />
          Open latest report
        </button>
      ) : null}
    </div>
  );
}

function IntelPanel({ state }: { state: DesktopState | undefined }) {
  return (
    <div className="panel">
      <PanelHeader icon={<Radar size={17} />} title="Security intel" subtitle="trusted feeds" />
      <div className="panel-list">
        {(state?.intel ?? []).map((item) => (
          <button className="intel-row" key={item.id} type="button" onClick={() => item.url ? window.open(item.url) : undefined}>
            <span className="source">{item.source}</span>
            <strong>{item.title}</strong>
            <p>{item.whyShown[0]}</p>
          </button>
        ))}
      </div>
    </div>
  );
}

function ReportsPanel({ reports }: { reports: ReportIndexEntry[] }) {
  return (
    <div className="panel">
      <PanelHeader icon={<History size={17} />} title="Reports" subtitle={`${reports.length} saved`} />
      <div className="panel-list">
        {reports.length === 0 ? <EmptyLine text="Saved reports will appear here." /> : null}
        {reports.map((report) => (
          <div className="report-row" key={report.scanId}>
            <div>
              <strong>{report.generatedAt}</strong>
              <p>{report.scanId}</p>
            </div>
            <button className="mini-button" type="button" onClick={() => void window.hermsec.openPath(report.htmlPath)}>
              Open
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function SettingsPanel(props: {
  state: DesktopState | undefined;
  draft: DesktopSettings | undefined;
  setDraft: (value: DesktopSettings) => void;
  save: () => Promise<void>;
}) {
  const draft = props.draft;
  if (!draft) {
    return (
      <div className="panel">
        <PanelHeader icon={<Settings size={17} />} title="Settings" subtitle="loading" />
      </div>
    );
  }
  const selectedProvider = props.state?.providerOptions.find((provider) => provider.id === draft.preferredModelProvider);
  return (
    <div className="panel">
      <PanelHeader icon={<Settings size={17} />} title="Settings" subtitle={props.state?.providerHealth.message ?? "provider"} />
      <label className="field">
        <span>Privacy</span>
        <select
          value={draft.privacyMode}
          onChange={(event) => props.setDraft({ ...draft, privacyMode: event.target.value as DesktopSettings["privacyMode"] })}
        >
          <option value="local-only">local-only</option>
          <option value="balanced">balanced</option>
          <option value="cloud-assisted">cloud-assisted</option>
        </select>
      </label>
      <label className="field">
        <span>Provider</span>
        <select
          value={draft.preferredModelProvider}
          onChange={(event) => props.setDraft({ ...draft, preferredModelProvider: event.target.value as DesktopSettings["preferredModelProvider"] })}
        >
          {(props.state?.providerOptions ?? []).map((provider) => (
            <option key={provider.id} value={provider.id}>{provider.label}</option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Model</span>
        <input
          value={draft.model}
          list="model-options"
          onChange={(event) => props.setDraft({ ...draft, model: event.target.value })}
        />
        <datalist id="model-options">
          {(selectedProvider?.models ?? []).map((model) => <option key={model} value={model} />)}
        </datalist>
      </label>
      <label className="field">
        <span>Credential env</span>
        <input
          value={draft.providerCredentialEnv ?? ""}
          placeholder="OPENCODE_GO_API_KEY"
          onChange={(event) => props.setDraft({ ...draft, providerCredentialEnv: event.target.value })}
        />
      </label>
      <label className="toggle-row">
        <input
          type="checkbox"
          checked={draft.allowRemoteProviders}
          onChange={(event) => props.setDraft({ ...draft, allowRemoteProviders: event.target.checked })}
        />
        <span>Allow remote model calls</span>
      </label>
      <label className="field">
        <span>Report directory</span>
        <input
          value={draft.customReportDir ?? ""}
          placeholder="default app data"
          onChange={(event) => props.setDraft({ ...draft, customReportDir: event.target.value })}
        />
      </label>
      <button className="wide-button primary" type="button" onClick={() => void props.save()}>
        <Save size={15} />
        Save settings
      </button>
    </div>
  );
}

function PanelHeader(props: { icon: ReactNode; title: string; subtitle: string }) {
  return (
    <div className="panel-header">
      <div className="panel-icon">{props.icon}</div>
      <div>
        <h2>{props.title}</h2>
        <p>{props.subtitle}</p>
      </div>
    </div>
  );
}

function Metric(props: { label: string; value: number; tone?: "danger" | "warn" }) {
  return (
    <div className={`metric ${props.tone ?? ""}`}>
      <span>{props.label}</span>
      <strong>{props.value}</strong>
    </div>
  );
}

function EmptyLine({ text }: { text: string }) {
  return (
    <div className="empty-line">
      <CheckCircle2 size={15} />
      <span>{text}</span>
    </div>
  );
}
