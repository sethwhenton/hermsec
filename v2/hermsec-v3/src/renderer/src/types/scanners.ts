export type ScannerCategory = "built-in" | "sast" | "secrets" | "sca" | "iac";
export type ScannerInstallKind = "built-in" | "native" | "python" | "npm" | "go" | "cargo" | "system";
export type ScannerStatus = "installed" | "missing" | "installing" | "failed" | "built-in";

export interface ScannerCatalogItem {
  id: string;
  label: string;
  category: ScannerCategory;
  command?: string;
  version?: string;
  installKind: ScannerInstallKind;
  languages: string[];
  inputs: string[];
  parser: string;
  defaultEnabled: boolean;
  autoInstall: boolean;
  riskNotes: string;
}

export interface ScannerUserSetting {
  id: string;
  enabled: boolean;
  autoInstall?: boolean;
}

export interface ScannerSettings {
  autoInstallMissing: boolean;
  allowOnlineUpdates: boolean;
  labInstallAll: boolean;
  items: ScannerUserSetting[];
}

export interface ScannerStatusItem extends ScannerCatalogItem {
  enabled: boolean;
  autoInstallSelected: boolean;
  status: ScannerStatus;
  managedPath?: string;
  systemPath?: string;
  versionDetected?: string;
  message: string;
  usedByCurrentProject?: boolean;
}

export interface ScannerActionRequest {
  scannerId: string;
}

export interface ScannerActionResult {
  ok: boolean;
  scannerId: string;
  message: string;
  status?: ScannerStatusItem;
}

export interface ScannerListRequest {
  projectPath?: string;
  labProfile?: boolean;
}
