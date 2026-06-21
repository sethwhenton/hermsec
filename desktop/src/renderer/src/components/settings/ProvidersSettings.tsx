import { CheckCircle2, Plus, Settings2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { requireHermsecApi } from "@/lib/ipc";
import { useSettingsStore } from "@/store/settingsStore";
import type { ProviderConfig, ProviderPreset } from "@/types/settings";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ProviderEditDrawer } from "./ProviderEditDrawer";
import { ProviderLogo } from "./ProviderLogo";

const authBadgeLabel: Record<ProviderConfig["authKind"], string> = {
  api_key: "API key",
  custom: "Custom",
  environment: "Environment",
};

function emptyProvider(): ProviderConfig {
  return {
    id: `custom-${Date.now()}`,
    displayName: "Custom Provider",
    baseUrl: "https://api.example.com/v1",
    apiFormat: "openai-compatible",
    authKind: "api_key",
    apiKeyEnvVar: "HERMSEC_MODEL_API_KEY",
    enabled: true,
    supportsModelDiscovery: true,
    models: [],
    modelDiscovery: { status: "idle" },
  };
}

export function ProvidersSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const [presets, setPresets] = useState<ProviderPreset[]>([]);
  const [editing, setEditing] = useState<ProviderConfig | null>(null);
  const [isNew, setIsNew] = useState(false);

  useEffect(() => {
    void requireHermsecApi().provider.presets().then(setPresets);
  }, []);

  const providersByPreset = useMemo(() => {
    const map = new Map<string, ProviderConfig>();
    for (const provider of settings?.providers ?? []) {
      map.set(provider.presetId ?? provider.id, provider);
    }
    return map;
  }, [settings?.providers]);

  if (!settings) return null;

  const handleDisconnect = (id: string) => {
    void update({
      providers: settings.providers.filter((provider) => provider.id !== id),
    });
  };

  const handleSave = (provider: ProviderConfig) => {
    const exists = settings.providers.some((item) => item.id === provider.id);
    const providers = exists
      ? settings.providers.map((item) => (item.id === provider.id ? provider : item))
      : [...settings.providers, provider];
    const activeModel = provider.models.find((model) => model.enabled);
    void update({
      providers,
      ...(activeModel && !settings.activeModelId ? { activeProviderId: provider.id, activeModelId: activeModel.id } : {}),
    });
  };

  const handlePreset = (preset: ProviderPreset) => {
    if (preset.status === "coming-soon") return;
    const existing = providersByPreset.get(preset.id);
    setEditing(existing ?? providerFromPreset(preset));
    setIsNew(!existing);
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-medium">Providers</h1>
          <p className="mt-1 text-xs text-muted">Choose a supported provider, add a key, and Hermsec will load available models.</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setEditing(emptyProvider());
            setIsNew(true);
          }}
        >
          <Plus className="h-3.5 w-3.5" />
          Custom provider
        </Button>
      </div>

      <div className="mb-3 text-xs font-medium text-muted">Supported providers</div>
      <div className="grid gap-3 sm:grid-cols-2">
        {presets.map((preset) => {
          const connected = providersByPreset.has(preset.id);
          const comingSoon = preset.status === "coming-soon";
          return (
            <button
              key={preset.id}
              type="button"
              disabled={comingSoon}
              onClick={() => handlePreset(preset)}
              className="group flex min-h-28 items-start gap-3 rounded-lg border border-border bg-surface px-3 py-3 text-left transition-colors duration-150 ease-out hover:border-foreground/20 hover:bg-white/[0.04] active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <ProviderLogo name={preset.displayName} logoUrl={preset.logoUrl} />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{preset.displayName}</span>
                  {connected && <CheckCircle2 className="h-3.5 w-3.5 text-success" />}
                </span>
                <span className="mt-1 line-clamp-2 text-xs text-muted">{preset.description}</span>
                <span className="mt-3 flex flex-wrap gap-1.5">
                  <Badge>{comingSoon ? "Coming soon" : connected ? "Configured" : "Preset"}</Badge>
                  {preset.supportsModelDiscovery && <Badge>{preset.models.length} defaults</Badge>}
                </span>
              </span>
            </button>
          );
        })}
      </div>

      <div className="mt-8 mb-3 text-xs font-medium text-muted">Connected providers</div>
      <div className="overflow-hidden rounded-lg border border-border">
        {settings.providers.map((provider, index) => (
          <div
            key={provider.id}
            className={`flex items-center gap-3 px-4 py-3 ${index > 0 ? "border-t border-border-subtle" : ""}`}
          >
            <ProviderLogo name={provider.displayName} logoUrl={provider.logoUrl} className="h-7 w-7" />
            <button
              type="button"
              className="flex min-w-0 flex-1 items-center gap-2 text-left"
              onClick={() => {
                setEditing(provider);
                setIsNew(false);
              }}
            >
              <span className="truncate text-sm text-foreground">{provider.displayName}</span>
              <Badge>{authBadgeLabel[provider.authKind]}</Badge>
              <Badge>{provider.models.length} models</Badge>
            </button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setEditing(provider);
                setIsNew(false);
              }}
            >
              <Settings2 className="h-3.5 w-3.5" />
              Edit
            </Button>
            <Button variant="ghost" size="sm" onClick={() => handleDisconnect(provider.id)}>
              Disconnect
            </Button>
          </div>
        ))}
        {settings.providers.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-muted">No providers configured.</div>
        )}
      </div>

      <ProviderEditDrawer
        open={editing !== null}
        provider={editing}
        isNew={isNew}
        onClose={() => setEditing(null)}
        onSave={handleSave}
      />
    </div>
  );
}

function providerFromPreset(preset: ProviderPreset): ProviderConfig {
  return {
    id: preset.id,
    displayName: preset.displayName,
    description: preset.description,
    baseUrl: preset.baseUrl,
    apiFormat: preset.apiFormat,
    presetId: preset.id,
    logoUrl: preset.logoUrl,
    authKind: "api_key",
    apiKeyEnvVar: preset.apiKeyEnvVar,
    enabled: preset.enabled,
    supportsModelDiscovery: preset.supportsModelDiscovery,
    models: preset.models,
    modelDiscovery: { status: "idle" },
  };
}
