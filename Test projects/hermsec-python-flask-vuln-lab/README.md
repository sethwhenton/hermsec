# Hermsec Python/Flask Vulnerable Lab

This is an intentionally vulnerable scanner-validation project. It contains toy local code paths and fake secrets only.

Do not deploy this app, do not reuse these patterns, and do not run package installs unless you are explicitly testing dependency handling in an isolated environment. The fixture is meant to be scanned as source code.

## Planted Issues

- Fake hardcoded fixture secrets in `app.py`.
- SQL query construction with untrusted request input.
- Shell command execution with request-controlled input.
- Dynamic Python execution through `eval`.
- Unsafe pickle deserialization of request data.
- Template rendering with unsanitized request input.
- Flask debug mode enabled.

Expected scanner metadata is in `expected-findings.json`.
