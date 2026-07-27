This directory contains the universal arm64/x86_64 macOS cleanup verifier
used when the npm package is built on a non-macOS host.

The binary is built from `scripts/darwin-fd-link-state.c` by
`scripts/build-darwin-fd-link-state.mjs`. The builder pins and verifies its
SHA-256 digest before copying it into the package. macOS builds compile the
same source directly and the release workflow verifies both architectures
with `lipo`.
