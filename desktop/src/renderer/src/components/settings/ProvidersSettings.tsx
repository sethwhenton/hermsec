import { Plus } from "lucide-react";
import { useState } from "react";
import { useSettingsStore } from "@/store/settingsStore";
import type { ProviderConfig } from "@/types/settings";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ProviderEditDrawer } from "./ProviderEditDrawer";

const authBadgeLabel: Record<ProviderConfig["authKind"], string> = {
  api_key: "API key",
  custom: "Custom",
  environment: "Environment",
};

function emptyProvider(): ProviderConfig {
  return {
    id: "new-provider",
    displayName: "New Provider",
    baseUrl: "https://api.opencode.ai/v1",
    authKind: "api_key",
    apiKeyEnvVar: "HERMSEC_MODEL_API_KEY",
    enabled: true,
    models: [],
  };
}

export function ProvidersSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const [editing, setEditing] = useState<ProviderConfig | null>(null);
  const [isNew, setIsNew] = useState(false);

  if (!settings) return null;

  const handleDisconnect = (id: string) => {
    void update({
      providers: settings.providers.filter((p) => p.id !== id),
    });
  };

  const handleSave = (provider: ProviderConfig) => {
    const exists = settings.providers.some((p) => p.id === provider.id);
    const providers = exists
      ? settings.providers.map((p) => (p.id === provider.id ? provider : p))
      : [...settings.providers, provider];
    void update({ providers });
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-medium">Providers</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setEditing(emptyProvider());
            setIsNew(true);
          }}
        >
          <Plus className="h-3.5 w-3.5" />
          Add provider
        </Button>
      </div>

      <div className="mb-3 text-xs font-medium text-muted">Connected providers</div>
      <div className="overflow-hidden rounded-lg border border-border">
        {settings.providers.map((provider, index) => (
          <div
            key={provider.id}
            className={`flex items-center gap-3 px-4 py-3 ${index > 0 ? "border-t border-border-subtle" : ""}`}
          >
            <div className="flex h-7 w-7 items-center justify-center rounded bg-white/5 text-xs font-medium">
              {provider.displayName.slice(0, 1)}
            </div>
            <button
              type="button"
              className="flex min-w-0 flex-1 items-center gap-2 text-left"
              onClick={() => {
                setEditing(provider);
                setIsNew(false);
              }}
            >
              <span className="text-sm text-foreground">{provider.displayName}</span>
              <Badge>{authBadgeLabel[provider.authKind]}</Badge>
            </button>
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
