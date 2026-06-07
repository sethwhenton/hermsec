# Hermsec V3

Standalone Electron chat shell with Codex/Cursor-style UI. UI only; backend agent plugs in via typed IPC and chat item unions.

## Run

```powershell
cd hermsec-v3
bun install
bun run dev
```

If you see a blank window or stale `getElectronPath` errors, use a clean dev start (kills old Electron, rebuilds `out/`):

```powershell
bun run dev:clean
```

If Electron fails to install (missing `path.txt` or `.pak` files), close all Electron windows first, then:

```powershell
Get-Process electron -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force node_modules\electron
bun install
bun run setup:electron
bun run dev
```

## Environment

Loads `.env.local` from the repo root (`v2/.env.local`):

- `HERMSEC_MODEL`
- `HERMSEC_MODEL_BASE_URL`
- `HERMSEC_MODEL_PROVIDER`
- `HERMSEC_MODEL_API_KEY` (optional, via `HERMSEC_MODEL_API_KEY_ENV`)

Provider **Test** validates connectivity from the main process against `{baseUrl}/models`.

## Agent plug-in surfaces

- `ChatItem` union in `src/renderer/src/types/chat.ts`
- `ContextBar` context chips in `uiStore.contextChips`
- `AgentQuestions` plan-mode Q&A card in the timeline
- `Spiral5x5` thinking loader when `uiStore.isAgentThinking` is true
- `window.hermsec` IPC API in `src/preload/index.ts`

## Settings persistence

`userData/settings.json` via main process store (`src/main/store.ts`).
