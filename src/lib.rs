#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/tcp-stream/0.1.0/")]

//! # Improve mio's TCP stream handling
//!
//! tcp-stream is a library aiming at providing TLS and futures/tokio
//! support to mio's TcpStream without forcibly using tokio-reactor

use cfg_if::cfg_if;
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
/// Reexport native-tls's TlsConnector
pub use native_tls::TlsConnector as NativeTlsConnector;

#[cfg(feature = "native-tls")]
/// A TcpStream wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<MioTcpStream>;

#[cfg(feature = "openssl")]
/// Reexport openssl's TlsConnector
pub use openssl::ssl::{SslConnector as OpenSslConnector, SslMethod as OpenSslMethod};

#[cfg(feature = "openssl")]
/// A TcpStream wrapped by openssl
pub type OpenSslStream = openssl::ssl::SslStream<MioTcpStream>;

/// Wrapper around plain or TLS TCP streams
pub enum TcpStream {
    /// Wrapper around mio's TcpStream
    Plain(MioTcpStream),
    #[cfg(feature = "native-tls")]
    /// Wrapper around a TLS stream hanled by native-tls
    NativeTls(NativeTlsStream),
    #[cfg(feature = "openssl")]
    /// Wrapper around a TLS stream hanled by openssl
    OpenSsl(OpenSslStream),
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
        into_tls_impl(self, domain)
    }

    #[cfg(feature = "native-tls")]
    /// Enable TLS using native-tls
    pub fn into_native_tls(self, connector: NativeTlsConnector, domain: &str) -> io::Result<Self> {
        match self {
            TcpStream::Plain(plain) => Ok(connector.connect(domain, plain).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.into()), // FIXME: retry auto on WouldBlock?
            _                       => Err(io::Error::new(io::ErrorKind::AlreadyExists, "already a TLS stream")),
        }
    }

    #[cfg(feature = "openssl")]
    /// Enable TLS using openssl
    pub fn into_openssl(self, connector: OpenSslConnector, domain: &str) -> io::Result<Self> {
        match self {
            TcpStream::Plain(plain) => Ok(connector.connect(domain, plain).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.into()), // FIXME: retry auto on WouldBlock?
            _                       => Err(io::Error::new(io::ErrorKind::AlreadyExists, "already a TLS stream")),
        }
    }
}

cfg_if! {
    if #[cfg(feature = "native-tls")] {
        fn into_tls_impl(s: TcpStream, domain: &str) -> io::Result<TcpStream> {
            s.into_native_tls(NativeTlsConnector::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?, domain)
        }
    } else if #[cfg(feature = "openssl")] {
        fn into_tls_impl(s: TcpStream, domain: &str) -> io::Result<TcpStream> {
            s.into_openssl(OpenSslConnector::builder(OpenSslMethod::tls()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?.build(), domain)
        }
    } else {
        fn into_tls_impl(_s: TcpStream, _domain: &str) -> io::Result<TcpStream> {
            Err(io::Error::new(io::ErrorKind::Other, "tls support disabled"))
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

#[cfg(feature = "openssl")]
impl From<OpenSslStream> for TcpStream {
    fn from(s: OpenSslStream) -> Self {
        TcpStream::OpenSsl(s)
    }
}

impl Deref for TcpStream {
    type Target = MioTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            TcpStream::Plain(plain)   => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_ref(),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(tls)   => tls.get_ref(),
        }
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            TcpStream::Plain(plain)   => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_mut(),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(tls)   => tls.get_mut(),
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.read(buf),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.read(buf),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(ref mut tls)   => tls.read(buf),
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.write(buf),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.write(buf),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(ref mut tls)   => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TcpStream::Plain(ref mut plain)   => plain.flush(),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.flush(),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(ref mut tls)   => tls.flush(),
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
