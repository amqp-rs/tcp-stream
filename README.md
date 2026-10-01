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
