import { CalendarClock, FolderOpen } from "lucide-react";
import { getHermsecApi } from "@/lib/ipc";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ScanModeSegmentedControl } from "@/components/scan/ScanModeSegmentedControl";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Toggle } from "@/components/ui/Toggle";

function SettingRow({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-border-subtle py-4">
      <div className="min-w-0 flex-1">
        <div className="text-sm text-foreground">{title}</div>
        <div className="mt-0.5 text-xs text-muted">{description}</div>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export function GeneralSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const setView = useUiStore((s) => s.setView);

  if (!settings) return null;

  const { general } = settings;
  const handleChooseReportDirectory = async () => {
    const api = getHermsecApi();
    if (!api) return;
    const directory = await api.settings.chooseReportDirectory(settings.defaultReportDir);
    if (directory) {
      await update({ defaultReportDir: directory });
    }
  };

  return (
    <div>
      <h1 className="mb-6 text-xl font-medium">General</h1>
      <SettingRow
        title="Language"
        description="The desktop interface currently stays in English. Translation support is planned."
      >
        <Select
          value="English"
          onChange={() => undefined}
          disabled
          options={[
            { value: "English", label: "English" },
          ]}
        />
      </SettingRow>
      <SettingRow
        title="Auto-accept permissions"
        description="Automatically accept permission prompts during agent runs."
      >
        <Toggle
          checked={general.autoAcceptPermissions}
          onChange={(autoAcceptPermissions) =>
            void update({ general: { ...general, autoAcceptPermissions } })
          }
        />
      </SettingRow>
      <SettingRow
        title="Terminal shell"
        description="Choose the shell used for your terminal and agent tool calls."
      >
        <Select
          value={general.terminalShell}
          onChange={(terminalShell) => void update({ general: { ...general, terminalShell } })}
          options={[
            { value: "Auto (Default)", label: "Auto (Default)" },
            { value: "PowerShell", label: "PowerShell" },
            { value: "bash", label: "bash" },
          ]}
        />
      </SettingRow>
      <SettingRow
        title="Privacy mode"
        description="Redact sensitive paths and secrets from reports and chat context."
      >
        <Toggle
          checked={general.privacyMode}
          onChange={(privacyMode) => void update({ general: { ...general, privacyMode } })}
        />
      </SettingRow>
      <SettingRow
        title="Scan mode"
        description="Default assistance level for chat and dashboard scans."
      >
        <div className="w-[420px]">
          <ScanModeSegmentedControl
            value={general.scanMode}
            onChange={(scanMode) => void update({ general: { ...general, scanMode } })}
          />
        </div>
      </SettingRow>
      <SettingRow
        title="Project directory"
        description="Local folder Hermsec scans when you ask the agent to scan the current project."
      >
        <Input
          className="w-96"
          value={settings.defaultProjectDir}
          onChange={(e) => void update({ defaultProjectDir: e.target.value })}
        />
      </SettingRow>
      <SettingRow
        title="Default report directory"
        description="Where Hermsec writes HTML and JSON security reports."
      >
        <div className="flex items-center gap-2">
          <Input
            className="w-72"
            value={settings.defaultReportDir}
            onChange={(e) => void update({ defaultReportDir: e.target.value })}
          />
          <Button
            variant="outline"
            size="icon"
            aria-label="Choose report directory"
            title="Choose report directory"
            onClick={() => {
              void handleChooseReportDirectory();
            }}
          >
            <FolderOpen className="h-4 w-4" />
          </Button>
        </div>
      </SettingRow>
      <SettingRow
        title="Automation"
        description="In-app schedule that checks project changes while Hermsec is open."
      >
        <div className="flex items-center gap-2">
          <span className="rounded-md border border-border bg-surface-elevated px-3 py-1.5 text-xs text-foreground">
            {settings.automation.enabled ? `${formatFrequency(settings.automation)} at ${settings.automation.time}` : "Disabled"}
          </span>
          <Button variant="outline" size="sm" onClick={() => setView("automations")}>
            <CalendarClock className="h-3.5 w-3.5" />
            Configure
          </Button>
        </div>
      </SettingRow>
    </div>
  );
}

function formatFrequency(automation: { frequency: string; intervalDays?: number }): string {
  if (automation.frequency === "weekly") return "Every week";
  if (automation.frequency === "monthly") return "Every month";
  const days = Math.min(365, Math.max(1, Math.floor(Number(automation.intervalDays ?? 1))));
  return days === 1 ? "Every day" : `Every ${days} days`;
}
