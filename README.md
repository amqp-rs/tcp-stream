<div align="center">

[![API Docs](https://docs.rs/tcp-stream/badge.svg)](https://docs.rs/tcp-stream)
[![Build status](https://github.com/amqp-rs/tcp-stream/workflows/Build%20and%20test/badge.svg)](https://github.com/amqp-rs/tcp-stream/actions)
[![Downloads](https://img.shields.io/crates/d/tcp-stream.svg)](https://crates.io/crates/tcp-stream)
[![Dependency Status](https://deps.rs/repo/github/amqp-rs/tcp-stream/status.svg)](https://deps.rs/repo/github/amqp-rs/tcp-stream)
[![LICENSE](https://img.shields.io/crates/l/tcp-stream)](LICENSE)

**A `TcpStream` with pluggable TLS support.**

</div>

Wraps `std::net::TcpStream` in a `TcpStream` enum that can be upgraded to a
TLS-encrypted stream via `TcpStream::into_tls`. Supported backends are rustls
(default), native-tls, and OpenSSL. Async `futures-io` trait implementations
are provided when the `futures` feature is enabled.

## Feature flags

### Async runtime (pick exactly one)

| Flag | Notes |
|------|-------|
| `tokio` *(default)* | Requires a running Tokio runtime |
| `smol` | Uses the smol executor |
| `async-global-executor` | Uses async-global-executor |

### TLS backend (pick at most one)

| Flag | Notes |
|------|-------|
| `rustls` *(default)* | TLS via rustls |
| `native-tls` | TLS via the platform's native library |
| `openssl` | TLS via OpenSSL |

### Rustls certificate store (when `rustls` is active)

| Flag | Notes |
|------|-------|
| `rustls-platform-verifier` *(default)* | Uses the platform trust store |
| `rustls-native-certs` | Loads native root certificates |
| `rustls-webpki-roots-certs` | Uses the webpki bundled root set |

Enable a certificate store or supply custom roots through `TLSConfig::cert_chain`.
Custom roots are added to the selected store; they do not replace it. A malformed
PEM certificate is an error, and a chain without certificates adds no roots.
Like OpenSSL, every backend reads the legacy `X509 CERTIFICATE` label but skips
`TRUSTED CERTIFICATE` objects, whose trust settings it does not apply. On Android, the platform verifier accepts no custom roots, so connecting
with them fails unless default features are disabled and another store is
selected.
When multiple store features are enabled, the priority is
`rustls-platform-verifier`, then `rustls-native-certs`, then
`rustls-webpki-roots-certs`.

### Rustls crypto provider (at least one required)

| Flag | Notes |
|------|-------|
| `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs |
| `rustls--ring` | Uses ring (more portable, e.g. builds on Windows) |

### Miscellaneous

| Flag | Notes |
|------|-------|
| `futures` | Enable `futures-io` async trait impls on the encrypted stream |
| `vendored-openssl` | Build a vendored OpenSSL (requires `openssl` feature) |

For client authentication with native-tls on Apple platforms other than macOS,
use a PKCS#12 identity. Configuring a PKCS#8 identity there returns `Unsupported`.
native-tls itself panics on Apple platforms for a PKCS#12 bundle without a
private key, and with OpenSSL 3 it sends a PKCS#12 bundle's extra certificates
root first; prefer PKCS#8 identities or the OpenSSL backend where these matter.
PKCS#8 identities require an unencrypted private key. Native TLS validates the
complete PKCS#8 DER structure and imports normalized PEM containing only the
validated key and certificates, reading the legacy `X509 CERTIFICATE` label as
OpenSSL does. Encrypted or malformed keys return
`InvalidData`, including encrypted DER mislabeled `PRIVATE KEY` and legacy
encryption headers; OpenSSL supplies an explicit empty passphrase, rejects
encrypted certificates, and also reports a certificate that does not match its
key as `InvalidData`. Every backend reports a malformed PKCS#12 bundle as
`InvalidData` too. Neither backend prompts
interactively for a decryption password. These checks apply to both synchronous
and async upgrades. Native TLS and OpenSSL reject NUL bytes in TLS domains and
PKCS#12 passwords with `InvalidInput`.

## Example

To connect to a remote server:

```rust
use tcp_stream::{TcpStream, TLSConfig};

use std::io::{Read, Write};

fn main() {
    let stream = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut stream = stream.into_tls("www.rust-lang.org", TLSConfig::default()).unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{}", String::from_utf8_lossy(&res));
}
```

For nonblocking streams, wait for readiness between handshake retries. Use
`write()` and keep the unsent suffix after each partial write; retrying the whole
buffer after `write_all()` returns `WouldBlock` can duplicate bytes already sent.
The readiness helpers check the raw TCP socket, so `is_readable()` does not account
for plaintext buffered by a TLS backend. Both helpers preserve application data and
do not block, except that `is_writable()` starts and waits for the deferred
handshake of a blocking TCP Fast Open socket. On targets without socket polling support, they fall back to
zero-length reads and writes, which can report readiness too early, and the read
can block a blocking socket.
Urgent data counts as readable only when `SO_OOBINLINE` is enabled.

`connect_timeout()` tries each resolved address in turn with the full timeout.

Identity `Debug` output redacts the certificate bundle, private key, and password.

## Tests

Tests use local listeners and test certificates. Run `cargo test --locked` for
the default backend or select a backend and runtime with `--no-default-features`
and `--features`. TLS regressions check handshakes, hostname verification, and
rejection of valid unrelated trust roots without external network access.
