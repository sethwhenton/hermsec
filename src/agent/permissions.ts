export type ToolPermission = {
  readWorkspace: boolean;
  readOutsideWorkspace: false;
  writeWorkspace: false;
  writeAppData: boolean;
  network: "none" | "trusted-intel" | "model-provider";
  requiresUserApproval: boolean;
  allowedInOfflineMode: boolean;
};

export type ToolContext = {
  workspaceRoot?: string;
  offlineMode: boolean;
  userApproved: boolean;
};

export function readOnlyPermission(overrides: Partial<Omit<ToolPermission, "readOutsideWorkspace" | "writeWorkspace">> = {}): ToolPermission {
  return {
    readWorkspace: true,
    readOutsideWorkspace: false,
    writeWorkspace: false,
    writeAppData: false,
    network: "none",
    requiresUserApproval: false,
    allowedInOfflineMode: true,
    ...overrides
  };
}

export function assertToolPermission(permission: ToolPermission, context: ToolContext): void {
  if (permission.readOutsideWorkspace) {
    throw new Error("Hermsec tools may not read outside the active workspace.");
  }
  if (permission.writeWorkspace) {
    throw new Error("Hermsec tools may not write to source workspaces.");
  }
  if (context.offlineMode && !permission.allowedInOfflineMode) {
    throw new Error("Tool is not allowed in offline mode.");
  }
  if (permission.requiresUserApproval && !context.userApproved) {
    throw new Error("Tool requires explicit user approval.");
  }
}
