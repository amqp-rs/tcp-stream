# std::net::TcpStream on steroids

[![API Docs](https://docs.rs/tcp-stream/badge.svg)](https://docs.rs/tcp-stream)
[![Build status](https://github.com/Keruspe/tcp-stream/workflows/Build%20and%20test/badge.svg)](https://github.com/Keruspe/tcp-stream/actions)
[![Downloads](https://img.shields.io/crates/d/tcp-stream.svg)](https://crates.io/crates/tcp-stream)

tcp-stream is a library aiming at providing TLS support to std::net::TcpStream

# Examples

To connect to a remote server:

```rust
use tcp_stream::{HandshakeError, TcpStream, TLSConfig};

use std::io::{self, Read, Write};

fn main() {
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = stream.into_tls("google.com", TLSConfig::default());

    while let Err(HandshakeError::WouldBlock(mid_handshake)) = stream {
        stream = mid_handshake.handshake();
    }

    let mut stream = stream.unwrap();

    while let Err(err) = stream.write_all(b"GET / HTTP/1.0\r\n\r\n") {
        if err.kind() != io::ErrorKind::WouldBlock {
            panic!("error: {:?}", err);
        }
    }
    stream.flush().unwrap();
    let mut res = vec![];
    while let Err(err) = stream.read_to_end(&mut res) {
        if err.kind() != io::ErrorKind::WouldBlock {
            panic!("stream error: {:?}", err);
        }
    }
    println!("{}", String::from_utf8_lossy(&res));
}
```
