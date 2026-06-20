# Installing Hermsec as an npm CLI

Hermsec's npm package is the scriptable scanner/report engine used by the V3 desktop app. The installed command is:

```powershell
hermsec
```

The desktop app is the primary user experience. The CLI remains useful for automation, benchmark runs, CI, and smoke checks.

## Scriptable Commands

```powershell
hermsec --help
hermsec doctor --json
hermsec scan C:\path\to\repo --mode online --out .hermsec\reports --md --html --json
hermsec report list
hermsec schedule list
hermsec intel update
hermsec eval run --suite .hermsec-benchmarks\BenchmarkJava
```

Running `hermsec` with no command prints help. Interactive chat and scanner-management UI live in the V3 desktop app under `desktop/`.

## Local Tarball Install

From the repository root:

```powershell
npm test
npm pack
npm install -g .\hermsec-0.1.0.tgz --ignore-scripts
hermsec --help
```

The tarball contains the compiled `dist/src` runtime and does not require package install scripts on the user's machine.

## Development Install

For local development on the same machine:

```powershell
npm test
npm link --ignore-scripts
hermsec --help
hermsec doctor --json
```

Use `npm unlink -g hermsec` when you want to remove the linked development command.

## Desktop App

For the full V3 app:

```powershell
npm run desktop:install
npm run desktop:dev
```

Packaging:

```powershell
npm run desktop:dist:win
npm run desktop:dist:mac
```

## Registry Install Later

After publishing the packed artifact to npm or GitHub Packages, installation becomes:

```powershell
npm install -g hermsec --ignore-scripts
hermsec --help
```

If the unscoped `hermsec` package name is unavailable on npm, publish under a scope, for example `@sethwhenton/hermsec`, while keeping the binary command name as `hermsec`.
