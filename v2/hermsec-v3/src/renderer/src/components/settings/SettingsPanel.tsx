import { AnimatePresence, motion } from "framer-motion";
import { useUiStore } from "@/store/uiStore";
import { GeneralSettings } from "./GeneralSettings";
import { ModelsSettings } from "./ModelsSettings";
import { ProvidersSettings } from "./ProvidersSettings";
import { SettingsSidebar } from "./SettingsSidebar";

export function SettingsPanel() {
  const section = useUiStore((s) => s.settingsSection);
  const setSettingsSection = useUiStore((s) => s.setSettingsSection);

  return (
    <div className="flex h-full bg-background">
      <SettingsSidebar section={section} onSectionChange={setSettingsSection} />
      <div className="min-w-0 flex-1 overflow-y-auto px-8 py-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={section}
            initial={{ opacity: 0, x: 8 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -8 }}
            transition={{ type: "spring", stiffness: 400, damping: 36 }}
            className="mx-auto max-w-2xl"
          >
            {section === "general" && <GeneralSettings />}
            {section === "providers" && <ProvidersSettings />}
            {section === "models" && <ModelsSettings />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
