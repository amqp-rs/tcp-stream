#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/tcp-stream/0.0.0/")]

//! # Improve mio's TCP stream handling
//!
//! tcp-stream is a library aiming at providing TLS and futures/tokio
//! support to mio's TcpStream without forcibly using tokio-reactor

use mio::{
    Evented, Poll, PollOpt, Ready, Token,
    tcp::TcpStream as MioTcpStream,
};
#[cfg(feature = "native-tls")]
use native_tls;

use std::{
    fmt,
    io::{self, Read, Write},
    net::{self, SocketAddr},
    ops::{Deref, DerefMut},
};

#[cfg(feature = "native-tls")]
/// Reexport native_tls's TlsConnector
pub use native_tls::TlsConnector as NativeTlsConnector;

#[cfg(feature = "native-tls")]
/// A TcpStream wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<MioTcpStream>;

/// Wrapper around plain or TLS TCP streams
pub enum TcpStream {
    /// Wrapper around mio's TcpStream
    Plain(MioTcpStream),
    #[cfg(feature = "native-tls")]
    /// Wrapper around a TLS stream hanled by native-tls
    NativeTls(NativeTlsStream),
}

impl TcpStream {
    /// Wrapper around mio's TcpStream::connect
    pub fn connect(addr: &SocketAddr) -> io::Result<Self> {
        Ok(MioTcpStream::connect(addr)?.into())
    }

    /// Wrapper around mio's TcpStream::connect_stream
    pub fn connect_stream(stream: net::TcpStream, addr: &SocketAddr) -> io::Result<Self> {
        Ok(MioTcpStream::connect_stream(stream, addr)?.into())
    }

    /// Wrapper around mio's TcpStream::from_stream
    pub fn from_stream(stream: net::TcpStream) -> io::Result<Self> {
        Ok(MioTcpStream::from_stream(stream)?.into())
    }

    /// Enable TLS
    pub fn into_tls(self, domain: &str) -> io::Result<Self> {
        #[cfg(feature = "native-tls")]
        return self.into_native_tls(NativeTlsConnector::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?, domain);
        #[cfg(not(any(feature = "native-tls")))]
        {
            let _ = domain;
            return Err(io::Error::new(io::ErrorKind::Other, "tls support disabled"));
        }
    }

    #[cfg(feature = "native-tls")]
    /// Enable TLS using native-tls
    pub fn into_native_tls(self, connector: NativeTlsConnector, domain: &str) -> io::Result<Self> {
        match self {
            TcpStream::Plain(plain) => Ok(connector.connect(domain, plain).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.into()), // FIXME: retry auto on WouldBlock?
            _                       => Err(io::Error::new(io::ErrorKind::AlreadyExists, "already a TLS stream")),
        }
    }
}

impl From<MioTcpStream> for TcpStream {
    fn from(s: MioTcpStream) -> Self {
        TcpStream::Plain(s)
    }
}

#[cfg(feature = "native-tls")]
impl From<NativeTlsStream> for TcpStream {
    fn from(s: NativeTlsStream) -> Self {
        TcpStream::NativeTls(s)
    }
}

impl Deref for TcpStream {
    type Target = MioTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            TcpStream::Plain(plain)   => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_ref(),
        }
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            TcpStream::Plain(plain) => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_mut(),
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.read(buf),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.read(buf),
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.write(buf),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.flush(),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.flush(),
        }
    }
}

impl Evented for TcpStream {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        <MioTcpStream as Evented>::register(self, poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        <MioTcpStream as Evented>::reregister(self, poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        poll.deregister(self)
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <MioTcpStream as fmt::Debug>::fmt(self, f)
    }
}

#[cfg(unix)]
mod unix;

#[cfg(feature = "tokio")]
mod tokio;
