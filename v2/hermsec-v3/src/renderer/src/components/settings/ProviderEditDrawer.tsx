import { CheckCircle2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { requireHermsecApi } from "@/lib/ipc";
import type { ProviderConfig, ProviderTestResult } from "@/types/settings";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import Spiral5x5 from "@/components/ui/Spiral5x5";

interface ProviderEditDrawerProps {
  open: boolean;
  provider: ProviderConfig | null;
  isNew?: boolean;
  onClose: () => void;
  onSave: (provider: ProviderConfig) => void;
}

type TestState = "idle" | "testing" | "success" | "error";

export function ProviderEditDrawer({
  open,
  provider,
  isNew,
  onClose,
  onSave,
}: ProviderEditDrawerProps) {
  const [draft, setDraft] = useState<ProviderConfig | null>(provider);
  const [testState, setTestState] = useState<TestState>("idle");
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);

  useEffect(() => {
    setDraft(provider);
    setTestState("idle");
    setTestResult(null);
  }, [provider, open]);

  if (!draft) return null;

  const handleTest = async () => {
    setTestState("testing");
    setTestResult(null);
    try {
      const result = await requireHermsecApi().provider.test({
        baseUrl: draft.baseUrl,
        apiKey: draft.apiKey,
        apiKeyEnvVar: draft.apiKeyEnvVar,
      });
      setTestResult(result);
      setTestState(result.ok ? "success" : "error");
    } catch (error) {
      setTestResult({
        ok: false,
        message: error instanceof Error ? error.message : "Test failed",
        latencyMs: 0,
      });
      setTestState("error");
    }
  };

  const handleSave = () => {
    onSave(draft);
    onClose();
  };

  return (
    <Drawer open={open} onClose={onClose} title={isNew ? "Add provider" : "Edit provider"}>
      <div className="space-y-4">
        <p className="text-xs text-muted">
          Configure an OpenAI-compatible provider. See the provider config docs.
        </p>

        <Field label="Provider ID" hint="Lowercase letters, numbers, hyphens, or underscores">
          <Input
            value={draft.id}
            disabled={!isNew}
            onChange={(e) => setDraft({ ...draft, id: e.target.value })}
          />
        </Field>

        <Field label="Display name">
          <Input
            value={draft.displayName}
            onChange={(e) => setDraft({ ...draft, displayName: e.target.value })}
          />
        </Field>

        <Field label="Base URL">
          <Input
            value={draft.baseUrl}
            onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })}
            placeholder="https://api.opencode.ai/v1"
          />
        </Field>

        <Field label="Auth kind">
          <Select
            value={draft.authKind}
            onChange={(authKind) =>
              setDraft({
                ...draft,
                authKind: authKind as ProviderConfig["authKind"],
              })
            }
            options={[
              { value: "api_key", label: "API key" },
              { value: "custom", label: "Custom" },
              { value: "environment", label: "Environment" },
            ]}
          />
        </Field>

        <Field label="API key environment variable name">
          <Input
            value={draft.apiKeyEnvVar ?? ""}
            onChange={(e) => setDraft({ ...draft, apiKeyEnvVar: e.target.value })}
            placeholder="HERMSEC_MODEL_API_KEY"
          />
        </Field>

        <Field label="API key" hint="Optional. Leave empty if you manage auth via environment.">
          <Input
            type="password"
            value={draft.apiKey ?? ""}
            onChange={(e) => setDraft({ ...draft, apiKey: e.target.value })}
            placeholder="••••••••••••"
          />
        </Field>

        {testState !== "idle" && (
          <div className="flex items-start gap-2 rounded-md border border-border bg-surface px-3 py-2">
            {testState === "testing" && <Spiral5x5 glow className="shrink-0" />}
            {testState === "success" && <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />}
            {testState === "error" && <XCircle className="h-4 w-4 shrink-0 text-danger" />}
            <div className="min-w-0 text-xs">
              {testState === "testing" && <span className="text-muted">Testing connection…</span>}
              {testResult && (
                <span className={testResult.ok ? "text-success" : "text-danger"}>
                  {testResult.message}
                  {testResult.latencyMs > 0 && ` (${testResult.latencyMs}ms)`}
                </span>
              )}
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <Button variant="outline" onClick={() => void handleTest()} disabled={testState === "testing"}>
            Test
          </Button>
          <Button onClick={handleSave}>Save</Button>
        </div>
      </div>
    </Drawer>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-foreground">{label}</span>
      {children}
      {hint && <span className="block text-[11px] text-muted">{hint}</span>}
    </label>
  );
}
