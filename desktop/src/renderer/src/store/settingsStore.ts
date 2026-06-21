import { create } from "zustand";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import type { AppSettings, DeepPartial } from "@/types/settings";

interface SettingsState {
  settings: AppSettings | null;
  loading: boolean;
  hydrated: boolean;
  hydrate: () => Promise<void>;
  update: (partial: DeepPartial<AppSettings>) => Promise<void>;
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  settings: null,
  loading: false,
  hydrated: false,
  hydrate: async () => {
    if (get().hydrated) return;
    const api = getHermsecApi();
    if (!api) {
      set({ loading: false, hydrated: true });
      return;
    }
    set({ loading: true });
    let settings = await api.settings.get();
    if (!settings.defaultProjectDir?.trim()) {
      const projects = await api.projects.list();
      if (projects.length === 1) {
        settings = await api.settings.set({ defaultProjectDir: projects[0].path });
      }
    }
    if (settings.defaultProjectDir?.trim()) {
      await api.projects.add(settings.defaultProjectDir);
    }
    set({ settings, loading: false, hydrated: true });
  },
  update: async (partial) => {
    set({ loading: true });
    const api = requireHermsecApi();
    const settings = await api.settings.set(partial);
    if (partial.defaultProjectDir?.trim()) {
      await api.projects.add(partial.defaultProjectDir);
    }
    set({ settings, loading: false, hydrated: true });
  },
}));
