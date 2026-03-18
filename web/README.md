# ygg-vanity web

Minimal Dioxus web UI for the wasm-friendly vanity generator.

## Dev

From the repository root:

```bash
cargo run -p ygg-vanity -- --template '200:?:?:?:dead:beef:?:?'
```

For the web app, use the Dioxus CLI from the `web/` directory:

```bash
cd web
dx serve --platform web
```

## Release-oriented wasm build

Build the core wasm-friendly library:

```bash
cargo build --lib --no-default-features --features wasm --target wasm32-unknown-unknown --profile wasm-release
```

Build the Dioxus web app:

```bash
cargo build -p ygg-vanity-web --target wasm32-unknown-unknown --profile wasm-release
```
