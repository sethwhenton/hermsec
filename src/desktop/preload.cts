const { contextBridge, ipcRenderer } = require("electron") as typeof import("electron");

type ScanWorkspaceInput = Record<string, unknown>;
type ChatTurnInput = Record<string, unknown>;
type SaveSettingsInput = Record<string, unknown>;
type HermsecDesktopBridge = {
  getState(): Promise<unknown>;
  pickWorkspace(): Promise<unknown>;
  addWorkspace(rootPath: string): Promise<unknown>;
  setActiveWorkspace(workspaceId: string): Promise<unknown>;
  scanWorkspace(input: ScanWorkspaceInput): Promise<unknown>;
  updateIntel(offline?: boolean): Promise<unknown>;
  runDoctor(): Promise<unknown>;
  ask(input: ChatTurnInput): Promise<unknown>;
  saveSettings(input: SaveSettingsInput): Promise<unknown>;
  openPath(filePath: string): Promise<void>;
  showInFolder(filePath: string): Promise<void>;
};

const bridge: HermsecDesktopBridge = {
  getState: () => ipcRenderer.invoke("hermsec:get-state"),
  pickWorkspace: () => ipcRenderer.invoke("hermsec:pick-workspace"),
  addWorkspace: (rootPath: string) => ipcRenderer.invoke("hermsec:add-workspace", rootPath),
  setActiveWorkspace: (workspaceId: string) => ipcRenderer.invoke("hermsec:set-active-workspace", workspaceId),
  scanWorkspace: (input: ScanWorkspaceInput) => ipcRenderer.invoke("hermsec:scan-workspace", input),
  updateIntel: (offline?: boolean) => ipcRenderer.invoke("hermsec:update-intel", offline),
  runDoctor: () => ipcRenderer.invoke("hermsec:run-doctor"),
  ask: (input: ChatTurnInput) => ipcRenderer.invoke("hermsec:ask", input),
  saveSettings: (input: SaveSettingsInput) => ipcRenderer.invoke("hermsec:save-settings", input),
  openPath: (filePath: string) => ipcRenderer.invoke("hermsec:open-path", filePath),
  showInFolder: (filePath: string) => ipcRenderer.invoke("hermsec:show-in-folder", filePath),
};

contextBridge.exposeInMainWorld("hermsec", bridge);
