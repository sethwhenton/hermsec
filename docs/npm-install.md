# Installing Hermsec as an npm CLI

Hermsec is packaged as a Node.js command-line app. The installed command is:

```powershell
hermsec
```

Running `hermsec` with no arguments opens the keyboard-first terminal chatbot UI. It uses a fixed input box, responsive layout, scrollable context, paste-friendly input, onboarding, settings, model/provider pickers, sessions, and the real scan/report adapters. Scriptable commands remain available for automation:

```powershell
hermsec doctor
hermsec scan E:\path\to\repo --mode online --out .hermsec\reports --md --html
hermsec report list
hermsec schedule list
hermsec intel update
```

Useful TUI commands:

```text
/help or /commands    Show every TUI command and safety boundary
/doctor               Check scanner and local readiness
/scan <path>          Scan a workspace with the real Hermsec harness
/intel                Refresh and summarize trusted security updates
/reports              Show local reports
/settings             Edit privacy, report, model, and provider settings
/settings report <x>  Set report location or a custom local report folder
/model                Pick the active model provider
/provider             Configure provider credential environment variables
/provider env <name>  Store an env var name, never a raw key
/history [count]      Show recent messages in the current session
/sessions             List saved sessions for the active workspace
/sessions current     Show the current session summary
/sessions new         Save the current session and start a fresh one
/exit                 Leave the TUI
```

First-run onboarding happens inside this same TUI view, so the setup flow looks and behaves like the main app instead of dropping into a plain prompt. Type the shown number choices, or rerun the view with `hermsec onboard`.

## Local tarball install

From the repository root:

```powershell
pmg npm test
npm pack
npm install -g .\hermsec-0.1.0.tgz --ignore-scripts
hermsec
```

The tarball contains the compiled `dist/src` runtime and does not require package install scripts on the user's machine.

## Development install

For local development on the same machine:

```powershell
pmg npm test
npm link --ignore-scripts
hermsec --help
hermsec
```

Use `npm unlink -g hermsec` when you want to remove the linked development command.

## Registry install later

After publishing the packed artifact to npm or GitHub Packages, installation becomes:

```powershell
npm install -g hermsec --ignore-scripts
hermsec
```

If the unscoped `hermsec` package name is unavailable on npm, publish under a scope, for example `@sethwhenton/hermsec`, while keeping the binary command name as `hermsec`.
