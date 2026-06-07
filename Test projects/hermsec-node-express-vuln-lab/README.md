# Hermsec Node/Express Vulnerable Lab

This is an intentionally vulnerable scanner-validation project. It contains toy local code paths and fake secrets only.

Do not deploy this app, do not reuse these patterns, and do not run package installs unless you are explicitly testing dependency handling in an isolated environment. The fixture is meant to be scanned as source code.

## Planted Issues

- Fake hardcoded fixture secrets in `src/server.js`.
- SQL query construction with untrusted request input.
- Shell command execution with request-controlled input.
- Dynamic JavaScript execution through `eval`.
- Reflected HTML built from request input.

Expected scanner metadata is in `expected-findings.json`.
