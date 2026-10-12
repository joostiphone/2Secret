# Contributing to 2Secret

Thanks for helping! Bug reports, translations, reviews of the security design
and pull requests are all welcome.

## Development setup

```sh
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
cargo install dioxus-cli --version 0.7.10 --locked   # or: cargo binstall dioxus-cli@0.7.10

# Linux only, for the desktop app:
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev
```

## Checks before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The client crate contains end-to-end tests that start a real server and run
the complete crypto; the CLI crate runs the real binary.

## Guidelines

- Keep `twosecret-core` free of I/O and platform code so it keeps working on
  every target (including WebAssembly).
- Never log or print secrets. Wrap new secret types so they are zeroized on
  drop and redacted in `Debug` output.
- Changes to cryptography or the sync protocol need tests and an update of
  [docs/SECURITY.md](docs/SECURITY.md) or [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- UI text goes through `i18n::t("key")`; add English and Dutch strings to
  `crates/app/src/i18n.rs` (a test fails when a key is missing).

## Translations

Adding a language means adding a variant to `Lang` and a column to the table
in `crates/app/src/i18n.rs`.

By contributing you agree that your contributions are licensed under the MIT
or Apache-2.0 license, at the user's option.

## Releasing

1. Update the version in `Cargo.toml` and add a section to `CHANGELOG.md`.
2. Start the **Release** workflow from the Actions tab (*Run workflow*, enter
   e.g. `v1.2.3`) or push a tag `v1.2.3`.
3. The workflow builds all installers and the Docker image and creates a
   draft release; check it and click *Publish release*.
