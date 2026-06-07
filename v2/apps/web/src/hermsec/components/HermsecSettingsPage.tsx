import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { SelectItem } from "~/components/ui/select";
import { Switch } from "~/components/ui/switch";
import {
  SettingsRow,
  SettingsSection,
} from "~/components/settings/SettingsPanelPrimitives";
import {
  SettingsSegmentedControl,
  SettingsSelectControl,
} from "~/components/settings/SettingControls";
import { SETTINGS_PAGE_BACKGROUND_CLASS_NAME } from "~/settingsPanelStyles";
import { useTheme } from "~/hooks/useTheme";
import { cn } from "~/lib/utils";
import type { HermsecSettingsState } from "../types";
import { HermsecPageShell } from "./HermsecPageShell";

type HermsecSettingsPageProps = {
  settings: HermsecSettingsState;
  onChange: (patch: Partial<HermsecSettingsState>) => void;
};

type ProviderOption = {
  id: string;
  label: string;
  local: boolean;
  credentialEnv?: string;
  credential?: "not-required" | "env-present" | "env-missing";
  credentialFingerprint?: string;
  ok: boolean;
  message: string;
  models: string[];
};

type ProviderStatusData = {
  configuredProvider: string;
  configuredModel: string;
  fallbackReason?: string;
  providers: ProviderOption[];
};

const PROVIDER_FALLBACKS: ProviderOption[] = [
  {
    id: "opencode-go",
    label: "OpenCode Go",
    local: false,
    credentialEnv: "OPENCODE_GO_API_KEY",
    credential: "env-missing",
    ok: false,
    message: "OpenCode Go key not verified yet.",
    models: ["deepseek-v4-flash", "deepseek-v4-pro", "kimi-k2.6", "glm-5.1"],
  },
  {
    id: "openai",
    label: "OpenAI",
    local: false,
    credentialEnv: "OPENAI_API_KEY",
    credential: "env-missing",
    ok: false,
    message: "OpenAI key not verified yet.",
    models: ["gpt-4.1-mini"],
  },
  {
    id: "claude",
    label: "Claude",
    local: false,
    credentialEnv: "ANTHROPIC_API_KEY",
    credential: "env-missing",
    ok: false,
    message: "Claude key not verified yet.",
    models: ["claude-sonnet-4-5"],
  },
  {
    id: "gemini",
    label: "Google Gemini",
    local: false,
    credentialEnv: "GEMINI_API_KEY",
    credential: "env-missing",
    ok: false,
    message: "Gemini key not verified yet.",
    models: ["gemini-2.5-flash"],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    local: false,
    credentialEnv: "OPENROUTER_API_KEY",
    credential: "env-missing",
    ok: false,
    message: "OpenRouter key not verified yet.",
    models: ["openai/gpt-4.1-mini"],
  },
  {
    id: "ollama",
    label: "Ollama",
    local: true,
    credential: "not-required",
    ok: true,
    message: "Local Ollama endpoint.",
    models: ["llama3.1"],
  },
  {
    id: "openai-compatible",
    label: "OpenAI-compatible",
    local: true,
    credential: "not-required",
    ok: true,
    message: "Local or self-hosted OpenAI-compatible endpoint.",
    models: ["local-model"],
  },
  {
    id: "none",
    label: "Scanner-only",
    local: true,
    credential: "not-required",
    ok: true,
    message: "No model calls. Hermsec uses deterministic scanner guidance only.",
    models: ["scanner-only"],
  },
];

const SCAN_MODE_OPTIONS = [
  { value: "offline", label: "Offline" },
  { value: "online", label: "Online" },
  { value: "auto", label: "Auto" },
] as const;

function providerBaseUrl(provider: string): string {
  if (provider === "ollama") return "http://localhost:11434/v1";
  if (provider === "openai-compatible") return "http://localhost:1234/v1";
  return "";
}

function providerAccent(option: ProviderOption): string {
  if (option.id === "none") return "Scanner";
  if (option.local) return "Local";
  return "Cloud";
}

function credentialLabel(option: ProviderOption): string {
  if (option.credential === "env-present") return "Connected";
  if (option.credential === "not-required") return "No key required";
  return "Needs key";
}

function mergeProviderOptions(status?: ProviderStatusData | null): ProviderOption[] {
  const byId = new Map(PROVIDER_FALLBACKS.map((option) => [option.id, option]));
  for (const option of status?.providers ?? []) {
    byId.set(option.id, {
      ...(byId.get(option.id) ?? option),
      ...option,
      models: option.models.length ? option.models : byId.get(option.id)?.models ?? [],
    });
  }
  return [...byId.values()];
}

export function HermsecSettingsPage({ settings, onChange }: HermsecSettingsPageProps) {
  const { theme, setTheme } = useTheme();
  const [providerStatus, setProviderStatus] = useState<ProviderStatusData | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [pendingApiKey, setPendingApiKey] = useState("");
  const [checkingProviders, setCheckingProviders] = useState(false);

  const refreshProviders = useCallback(async () => {
    const bridge = window.desktopBridge?.hermsec;
    if (!bridge?.getProviders) return;
    setCheckingProviders(true);
    setStatusError(null);
    try {
      const result = await bridge.getProviders();
      const data = result.parsed?.data;
      setProviderStatus(data && typeof data === "object" ? (data as ProviderStatusData) : null);
      if (!result.ok) {
        setStatusError(result.parsed?.message ?? "Provider status check failed.");
      }
    } catch (error) {
      setStatusError(error instanceof Error ? error.message : "Provider status check failed.");
    } finally {
      setCheckingProviders(false);
    }
  }, []);

  useEffect(() => {
    void refreshProviders();
  }, [refreshProviders]);

  const providerOptions = useMemo(() => mergeProviderOptions(providerStatus), [providerStatus]);
  const selectedProvider =
    providerOptions.find((option) => option.id === settings.provider) ?? providerOptions[0];
  const modelOptions = selectedProvider?.models.length ? selectedProvider.models : [settings.model];
  const needsKey =
    selectedProvider &&
    !selectedProvider.local &&
    selectedProvider.id !== "none" &&
    selectedProvider.credential !== "not-required";
  const showBaseUrl = settings.provider === "ollama" || settings.provider === "openai-compatible";

  function selectProvider(option: ProviderOption) {
    onChange({
      provider: option.id,
      model: option.models[0] ?? settings.model,
      apiKeyEnvVar: option.credentialEnv ?? "",
      baseUrl: providerBaseUrl(option.id),
    });
  }

  function saveApiKey() {
    const trimmed = pendingApiKey.trim();
    if (!trimmed || !selectedProvider) return;
    onChange({
      provider: selectedProvider.id,
      model: settings.model,
      apiKeyEnvVar: settings.apiKeyEnvVar || selectedProvider.credentialEnv || "",
      apiKeyValue: trimmed,
      baseUrl: settings.baseUrl,
    });
    setPendingApiKey("");
    window.setTimeout(() => {
      void refreshProviders();
    }, 500);
  }

  return (
    <div
      className={cn(
        "min-h-full",
        SETTINGS_PAGE_BACKGROUND_CLASS_NAME,
      )}
    >
      <HermsecPageShell className="space-y-1" maxWidthClassName="max-w-[980px]">
        <h1 className="text-lg font-semibold text-foreground/90">Settings</h1>
        <p className="pb-4 text-[length:var(--app-font-size-ui,12px)] text-muted-foreground/70">
          Configure Hermsec's security agent, local reports, scan posture, and automation defaults.
        </p>

        <SettingsSection title="Providers">
          <div className="space-y-2 px-3 pb-3">
            {providerOptions.map((option) => {
              const selected = option.id === settings.provider;
              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => selectProvider(option)}
                  className={cn(
                    "grid w-full grid-cols-[minmax(0,1fr)_auto] gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors",
                    selected
                      ? "border-cyan-400/45 bg-cyan-400/[0.075]"
                      : "border-[color:var(--color-border)] bg-white/[0.018] hover:bg-white/[0.04]",
                  )}
                >
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="text-[12px] font-medium text-foreground/90">
                        {option.label}
                      </span>
                      <span className="rounded-full bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-muted-foreground/70">
                        {providerAccent(option)}
                      </span>
                    </span>
                    <span className="mt-1 block truncate text-[11px] text-muted-foreground/62">
                      {option.message}
                    </span>
                  </span>
                  <span
                    className={cn(
                      "self-center rounded-full px-2 py-0.5 text-[10px]",
                      option.credential === "env-present"
                        ? "bg-emerald-400/12 text-emerald-300"
                        : option.credential === "not-required"
                          ? "bg-white/[0.06] text-muted-foreground/80"
                          : "bg-amber-400/12 text-amber-300",
                    )}
                  >
                    {credentialLabel(option)}
                  </span>
                </button>
              );
            })}
          </div>
          <SettingsRow
            title="Refresh provider status"
            description={
              providerStatus?.fallbackReason ??
              statusError ??
              "Checks configured credentials without exposing key values in the renderer."
            }
            control={
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={checkingProviders}
                onClick={() => void refreshProviders()}
              >
                {checkingProviders ? "Checking" : "Verify"}
              </Button>
            }
          />
        </SettingsSection>

        <SettingsSection title="Selected model">
          <SettingsRow
            title="Model"
            description="Default model used for Hermsec security-agent answers and report explanations."
            control={
              <SettingsSelectControl
                value={settings.model}
                ariaLabel="Model"
                valueContent={settings.model}
                onValueChange={(value) => onChange({ model: value })}
              >
                {modelOptions.map((model) => (
                  <SelectItem key={model} hideIndicator value={model}>
                    {model}
                  </SelectItem>
                ))}
              </SettingsSelectControl>
            }
          />
          {showBaseUrl ? (
            <SettingsRow
              title="Base URL"
              description="Local or self-hosted endpoint for Ollama and OpenAI-compatible providers."
              control={
                <Input
                  value={settings.baseUrl}
                  onChange={(event) => onChange({ baseUrl: event.target.value })}
                  className="h-7 w-64 rounded-lg text-[11px]"
                  placeholder={providerBaseUrl(settings.provider)}
                />
              }
            />
          ) : null}
        </SettingsSection>

        {needsKey ? (
          <SettingsSection title="API key">
            <SettingsRow
              title="Environment variable"
              description="Hermsec stores the env-var name in config and writes key values only to ignored .env.local."
              control={
                <Input
                  value={settings.apiKeyEnvVar}
                  onChange={(event) => onChange({ apiKeyEnvVar: event.target.value })}
                  className="h-7 w-52 rounded-lg text-[11px]"
                  placeholder={selectedProvider?.credentialEnv}
                />
              }
            />
            <SettingsRow
              title="Save key locally"
              description="Optional. The raw key is never committed and is cleared from this field after saving."
              control={
                <div className="flex items-center gap-2">
                  <Input
                    value={pendingApiKey}
                    type="password"
                    onChange={(event) => setPendingApiKey(event.target.value)}
                    className="h-7 w-52 rounded-lg text-[11px]"
                    placeholder="Paste API key"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={!pendingApiKey.trim() || !settings.apiKeyEnvVar.trim()}
                    onClick={saveApiKey}
                  >
                    Save
                  </Button>
                </div>
              }
            />
          </SettingsSection>
        ) : null}

        <SettingsSection title="Reports & privacy">
          <SettingsRow
            title="Default report directory"
            description="Where scan and automation reports are written locally."
            control={
              <Input
                value={settings.defaultReportDirectory}
                onChange={(event) => onChange({ defaultReportDirectory: event.target.value })}
                className="h-7 w-64 rounded-lg text-[11px]"
              />
            }
          />
          <SettingsRow
            title="Local-only mode"
            description="Blocks remote providers and keeps Hermsec on scanner-only or local models."
            control={
              <Switch
                checked={settings.privacyMode}
                onCheckedChange={(checked) => onChange({ privacyMode: checked })}
              />
            }
          />
          <SettingsRow
            title="Scan mode"
            description="Default connectivity posture for new scans."
            control={
              <SettingsSegmentedControl
                value={settings.scanMode}
                ariaLabel="Scan mode"
                options={SCAN_MODE_OPTIONS.map((option) => ({
                  value: option.value,
                  label: option.label,
                }))}
                onValueChange={(value) =>
                  onChange({ scanMode: value as HermsecSettingsState["scanMode"] })
                }
              />
            }
          />
        </SettingsSection>

        <SettingsSection title="Appearance">
          <SettingsRow
            title="Theme"
            description="Keep the native shell readable while Hermsec stays security-focused."
            control={
              <SettingsSegmentedControl
                value={theme}
                ariaLabel="Theme"
                options={[
                  { value: "system", label: "System" },
                  { value: "dark", label: "Dark" },
                  { value: "light", label: "Light" },
                ]}
                onValueChange={(value) => {
                  setTheme(value as "system" | "dark" | "light");
                }}
              />
            }
          />
        </SettingsSection>

        <SettingsSection title="Automation defaults">
          <SettingsRow
            title="Default schedule"
            description="Pre-filled schedule for newly created automations."
            control={
              <Input
                value={settings.automationDefaultSchedule}
                onChange={(event) =>
                  onChange({ automationDefaultSchedule: event.target.value })
                }
                className="h-7 w-44 rounded-lg text-[11px]"
              />
            }
          />
        </SettingsSection>
      </HermsecPageShell>
    </div>
  );
}
