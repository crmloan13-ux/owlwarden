# @dointhai/owlwarden-core-native

The prebuilt Rust engine behind [owlwarden](https://github.com/suthat/owlwarden),
exposed to Node through napi-rs.

**You almost certainly want [`owlwarden`](https://www.npmjs.com/package/owlwarden)
instead.** This package is the engine, not the tool: it takes and returns JSON
strings and has no command-line interface.

```bash
npm i -D owlwarden        # what you probably want
```

## How the binary gets to you

This package contains no binary itself. It is a small loader that requires the
right one at runtime from a per-platform package listed in
`optionalDependencies`:

| | |
|---|---|
| macOS | `x64`, `arm64` |
| Linux | `x64` and `arm64` glibc, `x64` musl |
| Windows | `x64`, `arm64` |

Your package manager installs only the one that matches. Nothing is compiled and
nothing is downloaded at install time — a `postinstall` that fetches a binary is
a supply-chain hole, and a security tool cannot ship one.

Binaries are built and published from CI with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements), so the
artifact can be traced to the commit and workflow that produced it.

If you installed with `--no-optional`, the loader cannot find its binary. That is
the usual cause of a load failure; reinstall without it.

## Licence

MIT OR Apache-2.0.
