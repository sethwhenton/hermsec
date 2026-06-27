import { AnimatePresence, motion } from "framer-motion";
import { useUiStore } from "@/store/uiStore";
import { AgentsSettings } from "./AgentsSettings";
import { GeneralSettings } from "./GeneralSettings";
import { ModelsSettings } from "./ModelsSettings";
import { ProvidersSettings } from "./ProvidersSettings";
import { ScannersSettings } from "./ScannersSettings";
import { SettingsSidebar } from "./SettingsSidebar";

export function SettingsPanel() {
  const section = useUiStore((s) => s.settingsSection);
  const setSettingsSection = useUiStore((s) => s.setSettingsSection);
  const setView = useUiStore((s) => s.setView);

  return (
    <div className="flex h-full bg-background">
      <SettingsSidebar
        section={section}
        onBack={() => setView("chat")}
        onSectionChange={setSettingsSection}
      />
      <div className="min-w-0 flex-1 overflow-y-auto px-8 py-6 lg:px-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={section}
            initial={{ opacity: 0, x: 8 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -8 }}
            transition={{ type: "spring", stiffness: 400, damping: 36 }}
            className="mx-auto w-full max-w-5xl"
          >
            {section === "general" && <GeneralSettings />}
            {section === "agents" && <AgentsSettings />}
            {section === "providers" && <ProvidersSettings />}
            {section === "models" && <ModelsSettings />}
            {section === "scanners" && <ScannersSettings />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
