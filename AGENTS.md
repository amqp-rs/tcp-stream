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
| `src/lib.rs` | Core types (`TcpStream`, `MidHandshakeTlsStream`, `HandshakeError`, `TLSConfig`, `Identity`), `Read`/`Write` impls via `fwd_impl!` macro, `into_tls_impl` dispatch, socket check selection and shared write probes |
| `src/rustix_checks.rs` | Socket readiness and connection checks through rustix |
| `src/probe_checks.rs` | Zero-length probe checks for targets without rustix support |
| `src/rustls_impl.rs` | rustls backend — re-exports, `RustlsConnectorConfig` helpers, `From` conversions |
| `src/native_tls_impl.rs` | native-tls backend |
| `src/openssl_impl.rs` | openssl backend |
| `src/futures.rs` | `AsyncTcpStream<S>` — async version using `futures-io` traits, same multi-backend pattern |
| `src/sys/unix.rs` | `AsFd`, `AsRawFd`, `FromRawFd` impls |
| `src/sys/windows.rs` | Windows equivalents |
| `src/tests.rs` | Socket regression tests |

### Feature flags

The `into_tls()` / `into_tls_impl()` method selects a backend at compile time via `cfg_if!` in priority order: `rustls-platform-verifier` → `rustls-native-certs` → `rustls-webpki-roots-certs` → `rustls` → `openssl` → `native-tls`.

Async runtime is selected via the `async-rs` crate: `tokio` (default), `smol`, or `async-global-executor`. The `-futures` suffix feature variants (`rustls-futures`, `native-tls-futures`, `openssl-futures`) enable async TLS for those backends.

Rustls requires a crypto provider feature: `rustls--aws_lc_rs` (default) or `rustls--ring`.

### TLS identity

`TLSConfig` carries an optional `Identity` (borrowed) or `OwnedIdentity` (owned). Both support two formats:
- `PKCS12` — DER-encoded bundle with a password
- `PKCS8` — PEM certificate + PEM key pair

### Socket behavior and tests

On Unix, `is_readable()` peeks at the next byte with
`recv(MSG_PEEK | MSG_DONTWAIT)`, through rustix's `net` feature, so its result
is what the next read would return. On Windows and WASI it polls the raw socket
through rustix with a zero timeout, as `is_writable()` does there and on Unix.
Other targets keep 0.34.14's zero-length read and write probes,
and `try_connect()` falls back to the write probe there and wherever the socket
does not report its peer (WASI preview 1). The socket check selection in
`src/lib.rs` picks `rustix_checks` or `probe_checks`, and the rustix entries in
`Cargo.toml` carry the same target list. rustix does not build on NuttX, QNX
(`qnx`, declared in `[lints.rust]` for older toolchains), RTEMS and VxWorks,
which keep the probes. Recompute the list with a nightly
`-Zbuild-std=std,panic_abort` check of the plaintext library on each Unix target
OS, keeping only those where std builds and rustix does not.
On Windows, request `POLLRDNORM` for reads: `POLLIN` also includes urgent data
that an ordinary read cannot consume unless `SO_OOBINLINE` is enabled. Cover
both inline and separate urgent-data delivery in the readiness tests.
ESP-IDF does not expose `POLLNVAL`; keep that flag check target-gated. Retry
`poll()` and the Unix peek on `EINTR` with `rustix::io::retry_on_intr`.
Connection status checks `peer_addr()`, so a full send buffer does not imply a
pending connection, and confirms a peer with a zero-length write, which reports
a local write shutdown or a pending socket error as 0.34.14 did; XNU reports
`EINVAL` instead of `ENOTCONN` once both directions are shut. An unconnected
socket with any poll event has finished its attempt: check the peer address
again, since the attempt can end between the checks, then the socket error.
Without either, let the zero-length write decide, as 0.34.14 did: it fails if
the attempt failed and its error was already retrieved, and it starts the
handshake of a TCP Fast Open socket that deferred it, which then reports
`EINPROGRESS` and counts as pending. `NotConnected` from that write is a failure
there, since the attempt ended.
`is_readable()` reports a socket readable whenever a read will not block. The
Unix peek returns data, EOF, `EAGAIN` or the error that a read would, so it keeps
Linux's EOF when a reset follows the peer's FIN, reads past a separately
delivered urgent byte, and reports `NotConnected` for a socket that never
connected; the tests cover these on Linux, and the unconnected socket on macOS
too. Linux clears the socket error that the peek
returns, while macOS and the BSDs keep it for the next read (documented).
Windows and WASI infer the result from the poll events instead: on a closed or
failed socket they return the socket error only when `FIONREAD` shows no queued
data, and the cases above are unverified there. `POLLERR` without a socket error
only reports queued notifications such as transmit timestamps, which a read does
not consume: report `WouldBlock`, as 0.34.14's zero-length read did, and never
invent an error.
Outside Windows, `POLLHUP` means that the local side can no longer send, so
`is_writable()` returns `BrokenPipe` without writing. Otherwise it confirms
`POLLOUT` (and `POLLHUP` on Windows) with a zero-length write, which sends
nothing but fails after a local write shutdown (Linux still reports `POLLOUT`)
or a reset whose error was already retrieved, and returns that error; a Fast
Open handshake that the write started reads as `WouldBlock`. Every check shares
`write_probe()`, which waits for such a handshake on a blocking socket. On
Windows it reports `WSAESHUTDOWN` as `BrokenPipe`, which the standard library
does not do at the 1.88 MSRV. WSAPoll
reports `POLLHUP` when only the peer stopped sending, so Windows never treats it
as closed for writing; when WSAPoll reports nothing, `is_writable()` still runs
the probe there to catch a local write shutdown, and it does not report failed connections before Windows
10 2004, so on Windows the readiness checks look for a socket error whenever the
socket is not ready, and `try_connect()` in every pending call. There,
`try_connect()` cannot tell a failed attempt from a pending one once its socket
error was retrieved. WSAPoll reports nothing after a local read shutdown either,
and no probe detects it without blocking, so `is_readable()` reports
`WouldBlock` there (documented). `is_readable()` also checks the raw socket and does not
account for buffered TLS plaintext.
`connect_timeout()` gives each resolved address the full timeout.
