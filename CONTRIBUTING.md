# Contributing to Rustinel

## Getting started

See [docs/development.md](docs/development.md) for the full build matrix, toolchain requirements, and fastest local build paths.

Quick start:
```sh
cargo check          # fast syntax + type check
cargo test           # run the test suite
cargo clippy --all-targets -- -D clippy::all
cargo fmt --all
```

For Linux eBPF development you need nightly Rust, `rust-src`, and `bpf-linker`. See `docs/development.md` for details.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes and ensure `cargo test`, `cargo clippy`, and `cargo fmt` all pass
3. Add or update tests if behaviour changed
4. **Add a label** to your PR before requesting review — this drives release notes:
   - `enhancement` — new feature
   - `bug` — bug fix
   - `refactor` — refactoring
   - `documentation` — docs only
   - `ci` — CI/CD changes
5. Open a PR against `main`

## Reporting security vulnerabilities

See [SECURITY.md](SECURITY.md). Do not open a public issue for security reports.
