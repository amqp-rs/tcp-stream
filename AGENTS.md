# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
cargo build                                              # build
cargo test                                               # run tests
cargo check --all --bins --examples --tests --all-features  # check all feature combinations
cargo clippy --all-features -- -W clippy::all            # lint (CI standard)
cargo fmt --all                                          # format
cargo fmt --all -- --check                               # check formatting without changing files
```

Minimum supported Rust version: **1.88.0** (Rust 2024 edition).

## Architecture

`tcp-stream` is a thin wrapper library that adds TLS support to `std::net::TcpStream`. The central type is the `TcpStream` enum (`#[non_exhaustive]`) with one variant per TLS backend:

- `Plain(StdTcpStream)` — always present
- `NativeTls(NativeTlsStream)` — feature `native-tls`
- `Openssl(OpensslStream)` — feature `openssl`
- `Rustls(RustlsStream)` — feature `rustls` (default)

The same pattern is repeated for `MidHandshakeTlsStream` (non-blocking handshake state) and `AsyncTcpStream<S>` (the async mirror of `TcpStream`).

### File layout

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core types (`TcpStream`, `MidHandshakeTlsStream`, `HandshakeError`, `TLSConfig`, `Identity`), `Read`/`Write` impls via `fwd_impl!` macro, `into_tls_impl` dispatch |
| `src/rustls_impl.rs` | rustls backend — re-exports, `RustlsConnectorConfig` helpers, `From` conversions |
| `src/native_tls_impl.rs` | native-tls backend |
| `src/openssl_impl.rs` | openssl backend |
| `src/futures.rs` | `AsyncTcpStream<S>` — async version using `futures-io` traits, same multi-backend pattern |
| `src/sys/unix.rs` | `AsFd`, `AsRawFd`, `FromRawFd` impls |
| `src/sys/windows.rs` | Windows equivalents |

### Feature flags

The `into_tls()` / `into_tls_impl()` method selects a backend at compile time via `cfg_if!` in priority order: `rustls` → `openssl` → `native-tls`. With no backend enabled it fails with `io::ErrorKind::Unsupported` rather than returning an unencrypted stream.

Independently, `select_connector_config()` in `src/rustls_impl.rs` picks the rustls trust store, also via `cfg_if!`, in priority order: `rustls-platform-verifier` → `rustls-native-certs` → `rustls-webpki-roots-certs` → `RustlsConnectorConfig::default()`.

Async runtime is selected via the `async-rs` crate: `tokio` (default), `smol`, or `async-global-executor`. The `-futures` suffix feature variants (`rustls-futures`, `native-tls-futures`, `openssl-futures`) enable async TLS for those backends.

Rustls requires a crypto provider feature: `rustls--aws_lc_rs` (default) or `rustls--ring`.

### TLS identity

`TLSConfig` carries an optional `Identity` (borrowed) or `OwnedIdentity` (owned). Both support two formats:
- `PKCS12` — DER-encoded bundle with a password
- `PKCS8` — PEM certificate + PEM key pair
