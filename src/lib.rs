#![deny(missing_docs)]
#![allow(clippy::large_enum_variant, clippy::result_large_err)]

//! # std::net::TCP stream on steroids
//!
//! tcp-stream is a library aiming at providing TLS support to std::net::TcpStream
//!
//! # Examples
//!
//! To connect to a remote server:
//!
//! ```rust
//! use tcp_stream::{HandshakeError, TcpStream, TLSConfig};
//!
//! use std::io::{self, Read, Write};
//!
//! let mut stream = TcpStream::connect("www.rust-lang.org:443").unwrap();
//! stream.set_nonblocking(true).unwrap();
//!
//! loop {
//!     if stream.try_connect().unwrap() {
//!         break;
//!     }
//! }
//!
//! let mut stream = stream.into_tls("www.rust-lang.org", TLSConfig::default());
//!
//! while let Err(HandshakeError::WouldBlock(mid_handshake)) = stream {
//!     stream = mid_handshake.handshake();
//! }
//!
//! let mut stream = stream.unwrap();
//!
//! while let Err(err) = stream.write_all(b"GET / HTTP/1.0\r\n\r\n") {
//!     if err.kind() != io::ErrorKind::WouldBlock {
//!         panic!("error: {:?}", err);
//!     }
//! }
//!
//! while let Err(err) = stream.flush() {
//!     if err.kind() != io::ErrorKind::WouldBlock {
//!         panic!("error: {:?}", err);
//!     }
//! }
//!
//! let mut res = vec![];
//! while let Err(err) = stream.read_to_end(&mut res) {
//!     if err.kind() != io::ErrorKind::WouldBlock {
//!         panic!("stream error: {:?}", err);
//!     }
//! }
//! println!("{}", String::from_utf8_lossy(&res));
//! ```

use cfg_if::cfg_if;
use std::{
    convert::TryFrom,
    error::Error,
    fmt,
    io::{self, IoSlice, IoSliceMut, Read, Write},
    net::{TcpStream as StdTcpStream, ToSocketAddrs},
    ops::{Deref, DerefMut},
    time::Duration,
};

#[cfg(feature = "rustls")]
mod rustls_impl;
#[cfg(feature = "rustls")]
pub use rustls_impl::*;

#[cfg(feature = "native-tls")]
mod native_tls_impl;
#[cfg(feature = "native-tls")]
pub use native_tls_impl::*;

#[cfg(feature = "openssl")]
mod openssl_impl;
#[cfg(feature = "openssl")]
pub use openssl_impl::*;

#[cfg(feature = "futures")]
mod futures;
#[cfg(feature = "futures")]
pub use futures::*;

/// Wrapper around plain or TLS TCP streams
#[non_exhaustive]
pub enum TcpStream {
    /// Wrapper around std::net::TcpStream
    Plain(StdTcpStream),
    #[cfg(feature = "native-tls")]
    /// Wrapper around a TLS stream hanled by native-tls
    NativeTls(NativeTlsStream),
    #[cfg(feature = "openssl")]
    /// Wrapper around a TLS stream hanled by openssl
    Openssl(OpensslStream),
    #[cfg(feature = "rustls")]
    /// Wrapper around a TLS stream hanled by rustls
    Rustls(RustlsStream),
}

/// Holds extra TLS configuration
#[derive(Default, Debug, PartialEq)]
pub struct TLSConfig<'data, 'key, 'chain> {
    /// Use for client certificate authentication
    pub identity: Option<Identity<'data, 'key>>,
    /// The custom certificates chain in PEM format
    pub cert_chain: Option<&'chain str>,
}

/// Holds extra TLS configuration
#[derive(Default, Debug, PartialEq)]
pub struct OwnedTLSConfig {
    /// Use for client certificate authentication
    pub identity: Option<OwnedIdentity>,
    /// The custom certificates chain in PEM format
    pub cert_chain: Option<String>,
}

impl OwnedTLSConfig {
    /// Get the ephemeral `TLSConfig` corresponding to the `OwnedTLSConfig`
    #[must_use]
    pub fn as_ref(&self) -> TLSConfig<'_, '_, '_> {
        TLSConfig {
            identity: self.identity.as_ref().map(OwnedIdentity::as_ref),
            cert_chain: self.cert_chain.as_deref(),
        }
    }
}

/// Holds one of:
/// - PKCS#12 DER-encoded identity and decryption password
/// - PKCS#8 PEM-encoded certificate and key (without decryption password)
#[derive(Debug, PartialEq)]
pub enum Identity<'data, 'key> {
    /// PKCS#12 DER-encoded identity with decryption password
    PKCS12 {
        /// PKCS#12 DER-encoded identity
        der: &'data [u8],
        /// Decryption password
        password: &'key str,
    },
    /// PEM encoded DER private key with PEM encoded certificate
    PKCS8 {
        /// PEM-encoded certificate
        pem: &'data [u8],
        /// PEM-encoded key
        key: &'key [u8],
    },
}

/// Holds one of:
/// - PKCS#12 DER-encoded identity and decryption password
/// - PKCS#8 PEM-encoded certificate and key (without decryption password)
#[derive(Debug, PartialEq)]
pub enum OwnedIdentity {
    /// PKCS#12 DER-encoded identity with decryption password
    PKCS12 {
        /// PKCS#12 DER-encoded identity
        der: Vec<u8>,
        /// Decryption password
        password: String,
    },
    /// PKCS#8 encoded DER private key with PEM encoded certificate
    PKCS8 {
        /// PEM-encoded certificate
        pem: Vec<u8>,
        /// PEM-encoded key
        key: Vec<u8>,
    },
}

impl OwnedIdentity {
    /// Get the ephemeral `Identity` corresponding to the `OwnedIdentity`
    #[must_use]
    pub fn as_ref(&self) -> Identity<'_, '_> {
        match self {
            Self::PKCS8 { pem, key } => Identity::PKCS8 { pem, key },
            Self::PKCS12 { der, password } => Identity::PKCS12 { der, password },
        }
    }
}

/// Holds either the TLS `TcpStream` result or the current handshake state
pub type HandshakeResult = Result<TcpStream, HandshakeError>;

impl TcpStream {
    /// Wrapper around `std::net::TcpStream::connect`
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        connect_std(addr, None).and_then(Self::try_from)
    }

    /// Wrapper around `std::net::TcpStream::connect_timeout`
    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        connect_std(addr, Some(timeout)).and_then(Self::try_from)
    }

    /// Convert from a `std::net::TcpStream`
    pub fn from_std(stream: StdTcpStream) -> io::Result<Self> {
        Self::try_from(stream)
    }

    /// Attempt reading from underlying stream, returning Ok(()) if the stream is readable
    pub fn is_readable(&self) -> io::Result<()> {
        self.deref().read(&mut []).map(|_| ())
    }

    /// Attempt writing to underlying stream, returning Ok(()) if the stream is writable
    pub fn is_writable(&mut self) -> io::Result<()> {
        is_writable(self.deref_mut())
    }

    /// Retry the connection. Returns:
    /// - Ok(true) if connected
    /// - Ok(false) if connecting
    /// - Err(_) if an error is encountered
    pub fn try_connect(&mut self) -> io::Result<bool> {
        try_connect(self)
    }

    /// Enable TLS
    pub fn into_tls(
        self,
        domain: &str,
        config: TLSConfig<'_, '_, '_>,
    ) -> Result<Self, HandshakeError> {
        into_tls_impl(self, domain, config)
    }

    #[cfg(feature = "native-tls")]
    /// Enable TLS using native-tls
    pub fn into_native_tls(
        self,
        connector: &NativeTlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "openssl")]
    /// Enable TLS using openssl
    pub fn into_openssl(
        self,
        connector: &OpensslConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "rustls")]
    /// Enable TLS using rustls
    pub fn into_rustls(
        self,
        connector: &RustlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[allow(irrefutable_let_patterns)]
    fn into_plain(self) -> Result<StdTcpStream, io::Error> {
        if let Self::Plain(plain) = self {
            Ok(plain)
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "already a TLS stream",
            ))
        }
    }
}

fn connect_std<A: ToSocketAddrs>(addr: A, timeout: Option<Duration>) -> io::Result<StdTcpStream> {
    let stream = connect_std_raw(addr, timeout)?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn connect_std_raw<A: ToSocketAddrs>(
    addr: A,
    timeout: Option<Duration>,
) -> io::Result<StdTcpStream> {
    if let Some(timeout) = timeout {
        let addrs = addr.to_socket_addrs()?;
        let mut err = None;
        for addr in addrs {
            match StdTcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok(stream),
                Err(error) => err = Some(error),
            }
        }
        Err(err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "couldn't resolve host")
        }))
    } else {
        StdTcpStream::connect(addr)
    }
}

fn try_connect(stream: &mut StdTcpStream) -> io::Result<bool> {
    match is_writable(stream) {
        Ok(()) => Ok(true),
        Err(err)
            if [io::ErrorKind::WouldBlock, io::ErrorKind::NotConnected].contains(&err.kind()) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn is_writable(stream: &mut StdTcpStream) -> io::Result<()> {
    stream.write(&[]).map(|_| ())
}

fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
    cfg_if! {
        if #[cfg(feature = "rustls-native-certs")] {
            into_rustls_impl(s, RustlsConnectorConfig::new_with_native_certs()?, domain, config)
        } else if #[cfg(feature = "rustls-webpki-roots-certs")] {
            into_rustls_impl(s, RustlsConnectorConfig::new_with_webpki_roots_certs(), domain, config)
        } else if #[cfg(feature = "rustls")] {
            into_rustls_impl(s, RustlsConnectorConfig::default(), domain, config)
        } else if #[cfg(feature = "openssl")] {
            into_openssl_impl(s, domain, config)
        } else if #[cfg(feature = "native-tls")] {
            into_native_tls_impl(s, domain, config)
        } else {
            let _ = (domain, config);
            Ok(TcpStream::Plain(s.into_plain()?))
        }
    }
}

impl TryFrom<StdTcpStream> for TcpStream {
    type Error = io::Error;

    fn try_from(s: StdTcpStream) -> io::Result<Self> {
        let mut this = Self::Plain(s);
        this.try_connect()?;
        Ok(this)
    }
}

impl Deref for TcpStream {
    type Target = StdTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Plain(plain) => plain,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(tls) => tls.get_ref(),
            #[cfg(feature = "openssl")]
            Self::Openssl(tls) => tls.get_ref(),
            #[cfg(feature = "rustls")]
            Self::Rustls(tls) => tls.get_ref(),
        }
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Plain(plain) => plain,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(tls) => tls.get_mut(),
            #[cfg(feature = "openssl")]
            Self::Openssl(tls) => tls.get_mut(),
            #[cfg(feature = "rustls")]
            Self::Rustls(tls) => tls.get_mut(),
        }
    }
}

macro_rules! fwd_impl {
    ($self:ident, $method:ident, $($args:expr),*) => {
        match $self {
            Self::Plain(plain) => plain.$method($($args),*),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(tls) => tls.$method($($args),*),
            #[cfg(feature = "openssl")]
            Self::Openssl(tls) => tls.$method($($args),*),
            #[cfg(feature = "rustls")]
            Self::Rustls(tls) => tls.$method($($args),*),
        }
    };
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        fwd_impl!(self, read, buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        fwd_impl!(self, read_vectored, bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        fwd_impl!(self, read_to_end, buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        fwd_impl!(self, read_to_string, buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        fwd_impl!(self, read_exact, buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        fwd_impl!(self, write, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        fwd_impl!(self, flush,)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        fwd_impl!(self, write_vectored, bufs)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        fwd_impl!(self, write_all, buf)
    }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        fwd_impl!(self, write_fmt, fmt)
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream")
            .field("inner", self.deref())
            .finish()
    }
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub enum MidHandshakeTlsStream {
    /// Not a TLS stream
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    /// A native-tls MidHandshakeTlsStream
    NativeTls(NativeTlsMidHandshakeTlsStream),
    #[cfg(feature = "openssl")]
    /// An openssl MidHandshakeTlsStream
    Openssl(OpensslMidHandshakeTlsStream),
    #[cfg(feature = "rustls")]
    /// A rustls-connector MidHandshakeTlsStream
    Rustls(RustlsMidHandshakeTlsStream),
}

impl MidHandshakeTlsStream {
    /// Get a reference to the inner stream
    #[must_use]
    pub fn get_ref(&self) -> &StdTcpStream {
        match self {
            Self::Plain(mid) => mid,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(mid) => mid.get_ref(),
            #[cfg(feature = "openssl")]
            Self::Openssl(mid) => mid.get_ref(),
            #[cfg(feature = "rustls")]
            Self::Rustls(mid) => mid.get_ref(),
        }
    }

    /// Get a mutable reference to the inner stream
    #[must_use]
    pub fn get_mut(&mut self) -> &mut StdTcpStream {
        match self {
            Self::Plain(mid) => mid,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(mid) => mid.get_mut(),
            #[cfg(feature = "openssl")]
            Self::Openssl(mid) => mid.get_mut(),
            #[cfg(feature = "rustls")]
            Self::Rustls(mid) => mid.get_mut(),
        }
    }

    /// Retry the handshake
    pub fn handshake(mut self) -> HandshakeResult {
        if !try_connect(self.get_mut())? {
            return Err(HandshakeError::WouldBlock(self));
        }

        Ok(match self {
            Self::Plain(mid) => mid,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(mid) => mid.handshake()?.into(),
            #[cfg(feature = "openssl")]
            Self::Openssl(mid) => mid.handshake()?.into(),
            #[cfg(feature = "rustls")]
            Self::Rustls(mid) => mid.handshake()?.into(),
        })
    }
}

impl From<TcpStream> for MidHandshakeTlsStream {
    fn from(mid: TcpStream) -> Self {
        Self::Plain(mid)
    }
}

impl fmt::Display for MidHandshakeTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MidHandshakeTlsStream")
    }
}

/// An error returned while performing the handshake
#[derive(Debug)]
pub enum HandshakeError {
    /// We hit WouldBlock during handshake
    WouldBlock(MidHandshakeTlsStream),
    /// We hit a critical failure
    Failure(io::Error),
}

impl HandshakeError {
    /// Try and get the inner mid handshake TLS stream from this error
    pub fn into_mid_handshake_tls_stream(self) -> io::Result<MidHandshakeTlsStream> {
        match self {
            Self::WouldBlock(mid) => Ok(mid),
            Self::Failure(error) => Err(error),
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WouldBlock(_) => f.write_str("WouldBlock hit during handshake"),
            Self::Failure(err) => f.write_fmt(format_args!("IO error: {err}")),
        }
    }
}

impl Error for HandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failure(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> Self {
        Self::Failure(err)
    }
}

mod sys;
