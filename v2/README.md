# Hermsec V2

Hermsec V2 is a whole-source Synara fork adapted into a local-first security-agent desktop app.

The v2 direction keeps Synara's mature Electron, sidebar, chat, settings, provider picker, transcript, and desktop IPC architecture, then grafts in Hermsec's scan harness, vulnerability intel, local reports, and constrained model-backed explanations.

## Current Status

- Product branding is Hermsec V2.
- The selected H/keyhole mark is used as the app logo path.
- The marketing app has been removed from the active fork.
- `desktopBridge.hermsec` exposes Doctor, Scan, and Intel bridge methods backed by the existing Hermsec CLI build.
- The first chat screen includes Hermsec Doctor, Scan Folder, and Intel quick actions.

## Development Notes

- Upstream MIT attribution is kept in `LICENSE`.
- Internal `@t3tools/*` scopes are intentionally preserved during the first fork pass to avoid breaking imports.
- Run dependency installation only after accepting Synara's Bun/remote-catalog dependency policy.
- See `docs/HERMSEC_V2_SCOPE.md` for the cut-down plan and safety notes.
