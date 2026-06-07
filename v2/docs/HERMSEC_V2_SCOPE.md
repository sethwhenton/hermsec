# Hermsec V2 Synara Fork Scope

Hermsec V2 starts as a whole-source Synara fork so we can keep the mature Electron, sidebar, chat, settings, provider picker, transcript, and desktop IPC architecture.

## Kept For V2

- Electron desktop shell.
- React chat workspace UI.
- Sidebar, settings, provider/model picker, transcript, composer, theme, and keyboard UX.
- Server/runtime architecture while Hermsec-specific tooling is being grafted in.
- Upstream MIT license and attribution.

## Removed Or Disabled

- Marketing app has been removed from the active fork.
- Marketing build/dev scripts have been removed from the root package scripts.
- Default product branding is changed to Hermsec V2.
- Default visible logo is changed to the H/keyhole mark selected for Hermsec.

## Hermsec Features To Graft In

- Workspace scan action backed by the existing Hermsec harness.
- Security intel/news panel backed by CISA KEV, OSV, GitHub Advisory, and NVD fetchers.
- Local report list/open actions for generated HTML/Markdown/JSON reports.
- Strict defensive-agent prompts that explain only scanner-backed evidence.
- Provider defaults for OpenCode Go `deepseek-v4-flash`, with env-only secrets.

## Current Safety Notes

- Do not commit `.env.local`, API keys, tokens, or generated app state.
- The fork currently keeps internal `@t3tools/*` package names to avoid breaking thousands of imports during the first pass.
- Synara's root uses Bun and remote catalog dependencies; install/build steps should be run through PMG after reviewing the lockfile and remote dependency policy.
