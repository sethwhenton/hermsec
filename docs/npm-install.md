# Installing Hermsec as an npm CLI

Hermsec is packaged as a Node.js command-line app. The installed command is:

```powershell
hermsec
```

Running `hermsec` with no arguments opens the interactive chatbot/TUI. Scriptable commands remain available for automation:

```powershell
hermsec doctor
hermsec scan E:\path\to\repo --mode online --out .hermsec\reports --md --html
hermsec report list
hermsec schedule list
hermsec intel update
```

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
