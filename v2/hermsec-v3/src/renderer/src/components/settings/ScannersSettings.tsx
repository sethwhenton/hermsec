import { Download, RefreshCw, Search, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { requireHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import { useSettingsStore } from "@/store/settingsStore";
import type { ScannerStatusItem } from "@/types/scanners";

type Filter = "all" | "installed" | "missing" | "enabled" | "project";

const filters: Array<{ id: Filter; label: string }> = [
  { id: "all", label: "All" },
  { id: "installed", label: "Installed" },
  { id: "missing", label: "Missing" },
  { id: "enabled", label: "Enabled" },
  { id: "project", label: "Used by project" },
];

export function ScannersSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [scanners, setScanners] = useState<ScannerStatusItem[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionMessages, setActionMessages] = useState<Record<string, { ok: boolean; message: string }>>({});

  const refresh = async () => {
    if (!settings) return;
    setLoading(true);
    try {
      const list = await requireHermsecApi().scanners.list({ projectPath: settings.defaultProjectDir });
      setScanners(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings?.defaultProjectDir, settings?.scanners]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scanners.filter((scanner) => {
      const haystack = [
        scanner.label,
        scanner.id,
        scanner.category,
        scanner.command,
        scanner.languages.join(" "),
        scanner.inputs.join(" "),
      ].join(" ").toLowerCase();
      if (q && !haystack.includes(q)) return false;
      if (filter === "installed") return scanner.status === "installed" || scanner.status === "built-in";
      if (filter === "missing") return scanner.status === "missing" || scanner.status === "failed";
      if (filter === "enabled") return scanner.enabled;
      if (filter === "project") return Boolean(scanner.usedByCurrentProject);
      return true;
    });
  }, [filter, query, scanners]);

  if (!settings) return null;

  const updateScannerItem = (scannerId: string, patch: { enabled?: boolean; autoInstall?: boolean }) => {
    const existing = settings.scanners.items;
    void updateSettings({
      scanners: {
        ...settings.scanners,
        items: existing.map((item) => item.id === scannerId ? { ...item, ...patch } : item),
      },
    });
  };

  const updateGlobal = (patch: Partial<typeof settings.scanners>) => {
    void updateSettings({ scanners: { ...settings.scanners, ...patch } });
  };

  const runAction = async (scannerId: string, action: "install" | "uninstall" | "update") => {
    setBusyId(scannerId);
    try {
      const api = requireHermsecApi().scanners;
      const result =
        action === "install" ? await api.install(scannerId)
          : action === "uninstall" ? await api.uninstall(scannerId)
            : await api.update(scannerId);
      setActionMessages((current) => ({ ...current, [scannerId]: { ok: result.ok, message: result.message } }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div>
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-medium">Scanners</h1>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            HermSec selects only the scanners that match the current project. Managed installs stay inside HermSec.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={loading}>
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      <div className="mb-5 space-y-3">
        <ScannerSwitch
          label="Auto-install missing scanners"
          detail="When enabled, scan preparation can install supported missing tools for the detected project."
          checked={settings.scanners.autoInstallMissing}
          onChange={(checked) => updateGlobal({ autoInstallMissing: checked })}
        />
        <ScannerSwitch
          label="Allow online advisory updates"
          detail="Dependency scanners may refresh vulnerability databases when they need network data."
          checked={settings.scanners.allowOnlineUpdates}
          onChange={(checked) => updateGlobal({ allowOnlineUpdates: checked })}
        />
        <ScannerSwitch
          label="Benchmark lab: install all"
          detail="Temporary lab mode for benchmark runs. Normal scans stay adaptive."
          checked={settings.scanners.labInstallAll}
          onChange={(checked) => updateGlobal({ labInstallAll: checked })}
        />
      </div>

      <div className="relative mb-3">
        <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          className="pl-9"
          placeholder="Search scanners"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <div className="mb-4 flex flex-wrap gap-1">
        {filters.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setFilter(item.id)}
            className={cn(
              "rounded-md px-2.5 py-1 text-xs transition-colors",
              filter === item.id ? "bg-white/10 text-foreground" : "text-muted hover:bg-white/5 hover:text-foreground",
            )}
          >
            {item.label}
          </button>
        ))}
      </div>

      <div className="overflow-hidden rounded-lg border border-border">
        {visible.map((scanner, index) => (
          <ScannerRow
            key={scanner.id}
            scanner={scanner}
            busy={busyId === scanner.id}
            actionMessage={actionMessages[scanner.id]}
            className={index > 0 ? "border-t border-border-subtle" : ""}
            onEnabled={(enabled) => updateScannerItem(scanner.id, { enabled })}
            onAutoInstall={(autoInstall) => updateScannerItem(scanner.id, { autoInstall })}
            onInstall={() => void runAction(scanner.id, "install")}
            onUpdate={() => void runAction(scanner.id, "update")}
            onUninstall={() => void runAction(scanner.id, "uninstall")}
          />
        ))}
        {visible.length === 0 && (
          <div className="px-4 py-8 text-center text-xs text-muted">No scanners match this view.</div>
        )}
      </div>
    </div>
  );
}

function ScannerSwitch({
  label,
  detail,
  checked,
  onChange,
}: {
  label: string;
  detail: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-md border border-border-subtle px-3 py-2.5">
      <div>
        <div className="text-sm text-foreground">{label}</div>
        <div className="mt-0.5 text-xs text-muted-foreground">{detail}</div>
      </div>
      <Toggle checked={checked} onChange={onChange} />
    </div>
  );
}

function ScannerRow({
  scanner,
  busy,
  actionMessage,
  className,
  onEnabled,
  onAutoInstall,
  onInstall,
  onUpdate,
  onUninstall,
}: {
  scanner: ScannerStatusItem;
  busy: boolean;
  actionMessage?: { ok: boolean; message: string };
  className?: string;
  onEnabled: (enabled: boolean) => void;
  onAutoInstall: (enabled: boolean) => void;
  onInstall: () => void;
  onUpdate: () => void;
  onUninstall: () => void;
}) {
  const canInstall = scanner.installKind !== "built-in" && scanner.status !== "installed";
  const canRemove = Boolean(scanner.managedPath);
  return (
    <div className={cn("px-4 py-3", className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-medium text-foreground">{scanner.label}</h2>
            <StatusPill scanner={scanner} />
            {scanner.usedByCurrentProject && <span className="rounded bg-white/5 px-1.5 py-0.5 text-[10px] text-muted">project</span>}
          </div>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">{scanner.riskNotes}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {[scanner.category, scanner.installKind, ...scanner.languages.slice(0, 4), ...scanner.inputs.slice(0, 3)].map((chip) => (
              <span key={chip} className="rounded border border-border-subtle px-1.5 py-0.5 text-[10px] text-muted">
                {chip}
              </span>
            ))}
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground">{scanner.message}</div>
          {actionMessage && (
            <div className={cn("mt-1 text-[11px]", actionMessage.ok ? "text-muted-foreground" : "text-amber-300")}>
              {actionMessage.message}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Toggle checked={scanner.enabled} onChange={onEnabled} />
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          <Toggle checked={scanner.autoInstallSelected} onChange={onAutoInstall} disabled={scanner.installKind === "system" || scanner.installKind === "built-in"} />
          Auto-install
        </label>
        <div className="flex flex-wrap gap-1.5">
          {canInstall && (
            <Button variant="outline" size="sm" onClick={onInstall} disabled={busy}>
              <Download className="h-3.5 w-3.5" />
              {scanner.installKind === "native" || scanner.installKind === "cargo" || scanner.installKind === "system" ? "Check" : "Install"}
            </Button>
          )}
          {scanner.status === "installed" && scanner.installKind !== "system" && scanner.installKind !== "built-in" && (
            <Button variant="ghost" size="sm" onClick={onUpdate} disabled={busy}>
              <RefreshCw className={cn("h-3.5 w-3.5", busy && "animate-spin")} />
              Update
            </Button>
          )}
          {canRemove && (
            <Button variant="ghost" size="sm" onClick={onUninstall} disabled={busy}>
              <Trash2 className="h-3.5 w-3.5" />
              Remove
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function StatusPill({ scanner }: { scanner: ScannerStatusItem }) {
  const label = scanner.status === "built-in" ? "Built-in" : scanner.status === "installed" ? "Installed" : scanner.status === "missing" ? "Missing" : scanner.status;
  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-[10px]",
        scanner.status === "installed" || scanner.status === "built-in"
          ? "bg-white/8 text-foreground"
          : "bg-white/5 text-muted-foreground",
      )}
    >
      {label}
    </span>
  );
}
