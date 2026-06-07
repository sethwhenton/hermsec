import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useSettingsStore } from "@/store/settingsStore";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";

export function ModelsSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const [query, setQuery] = useState("");

  const filteredProviders = useMemo(() => {
    if (!settings) return [];
    const q = query.trim().toLowerCase();
    if (!q) return settings.providers;
    return settings.providers
      .map((provider) => ({
        ...provider,
        models: provider.models.filter(
          (m) => m.label.toLowerCase().includes(q) || m.id.toLowerCase().includes(q),
        ),
      }))
      .filter((p) => p.models.length > 0 || p.displayName.toLowerCase().includes(q));
  }, [settings, query]);

  if (!settings) return null;

  const toggleModel = (providerId: string, modelId: string, enabled: boolean) => {
    const providers = settings.providers.map((provider) => {
      if (provider.id !== providerId) return provider;
      return {
        ...provider,
        models: provider.models.map((model) =>
          model.id === modelId ? { ...model, enabled } : model,
        ),
      };
    });
    void update({ providers });
  };

  const setActiveModel = (modelId: string) => {
    void update({ activeModelId: modelId });
  };

  return (
    <div>
      <h1 className="mb-6 text-xl font-medium">Models</h1>
      <div className="relative mb-6">
        <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          className="pl-9"
          placeholder="Search models"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <div className="space-y-6">
        {filteredProviders.map((provider) => (
          <section key={provider.id}>
            <div className="mb-2 flex items-center gap-2">
              <div className="flex h-6 w-6 items-center justify-center rounded bg-white/5 text-[10px] font-medium">
                {provider.displayName.slice(0, 1)}
              </div>
              <h2 className="text-sm font-medium">{provider.displayName}</h2>
            </div>
            <div className="overflow-hidden rounded-lg border border-border">
              {provider.models.map((model, index) => (
                <div
                  key={model.id}
                  className={`flex items-center justify-between px-4 py-2.5 ${index > 0 ? "border-t border-border-subtle" : ""}`}
                >
                  <button
                    type="button"
                    className="text-left text-sm text-foreground hover:underline"
                    onClick={() => setActiveModel(model.id)}
                  >
                    {model.label}
                    {settings.activeModelId === model.id && (
                      <span className="ml-2 text-[10px] text-accent">active</span>
                    )}
                  </button>
                  <Toggle
                    checked={model.enabled}
                    onChange={(enabled) => toggleModel(provider.id, model.id, enabled)}
                  />
                </div>
              ))}
              {provider.models.length === 0 && (
                <div className="px-4 py-6 text-center text-xs text-muted">No models for this provider.</div>
              )}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
