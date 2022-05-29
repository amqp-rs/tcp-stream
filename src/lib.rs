#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/tcp-stream/0.24.3/")]

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
//! fn main() {
//!     let mut stream = TcpStream::connect("google.com:443").unwrap();
//!     stream.set_nonblocking(true).unwrap();
//!
//!     while !stream.is_connected() {
//!         if stream.try_connect().unwrap() {
//!             break;
//!         }
//!     }
//!
//!     let mut stream = stream.into_tls("google.com", TLSConfig::default());
//!
//!     while let Err(HandshakeError::WouldBlock(mid_handshake)) = stream {
//!         stream = mid_handshake.handshake();
//!     }
//!
//!     let mut stream = stream.unwrap();
//!
//!     while let Err(err) = stream.write_all(b"GET / HTTP/1.0\r\n\r\n") {
//!         if err.kind() != io::ErrorKind::WouldBlock {
//!             panic!("error: {:?}", err);
//!         }
//!     }
//!     stream.flush().unwrap();
//!     let mut res = vec![];
//!     while let Err(err) = stream.read_to_end(&mut res) {
//!         if err.kind() != io::ErrorKind::WouldBlock {
//!             panic!("stream error: {:?}", err);
//!         }
//!     }
//!     println!("{}", String::from_utf8_lossy(&res));
//! }
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

#[cfg(feature = "native-tls")]
use native_tls_crate as native_tls;

#[cfg(feature = "native-tls")]
/// Reexport native-tls's `TlsConnector`
pub use native_tls::TlsConnector as NativeTlsConnector;

#[cfg(feature = "native-tls")]
/// A `TcpStream` wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<TcpStream>;

#[cfg(feature = "native-tls")]
/// A `MidHandshakeTlsStream` from native-tls
pub type NativeTlsMidHandshakeTlsStream = native_tls::MidHandshakeTlsStream<TcpStream>;

#[cfg(feature = "native-tls")]
/// A `HandshakeError` from native-tls
pub type NativeTlsHandshakeError = native_tls::HandshakeError<TcpStream>;

#[cfg(feature = "openssl")]
/// Reexport openssl's `TlsConnector`
pub use openssl::ssl::{SslConnector as OpenSslConnector, SslMethod as OpenSslMethod};

#[cfg(feature = "openssl")]
/// A `TcpStream` wrapped by openssl
pub type OpenSslStream = openssl::ssl::SslStream<TcpStream>;

#[cfg(feature = "openssl")]
/// A `MidHandshakeTlsStream` from openssl
pub type OpenSslMidHandshakeTlsStream = openssl::ssl::MidHandshakeSslStream<TcpStream>;

#[cfg(feature = "openssl")]
/// A `HandshakeError` from openssl
pub type OpenSslHandshakeError = openssl::ssl::HandshakeError<TcpStream>;

#[cfg(feature = "openssl")]
/// An `ErrorStack` from openssl
pub type OpenSslErrorStack = openssl::error::ErrorStack;

#[cfg(feature = "rustls-connector")]
/// Reexport rustls-connector's `TlsConnector`
pub use rustls_connector::{RustlsConnector, RustlsConnectorConfig};

#[cfg(feature = "rustls-connector")]
/// A `TcpStream` wrapped by rustls
pub type RustlsStream = rustls_connector::TlsStream<TcpStream>;

#[cfg(feature = "rustls-connector")]
/// A `MidHandshakeTlsStream` from rustls-connector
pub type RustlsMidHandshakeTlsStream = rustls_connector::MidHandshakeTlsStream<TcpStream>;

#[cfg(feature = "rustls-connector")]
/// A `HandshakeError` from rustls-connector
pub type RustlsHandshakeError = rustls_connector::HandshakeError<TcpStream>;

/// Wrapper around plain or TLS TCP streams
pub enum TcpStream {
    /// Wrapper around std::net::TcpStream
    Plain(StdTcpStream, bool),
    #[cfg(feature = "native-tls")]
    /// Wrapper around a TLS stream hanled by native-tls
    NativeTls(Box<NativeTlsStream>),
    #[cfg(feature = "openssl")]
    /// Wrapper around a TLS stream hanled by openssl
    OpenSsl(Box<OpenSslStream>),
    #[cfg(feature = "rustls-connector")]
    /// Wrapper around a TLS stream hanled by rustls
    Rustls(Box<RustlsStream>),
}

/// Holds extra TLS configuration
#[derive(Default, Debug, PartialEq)]
pub struct TLSConfig<'der, 'pass, 'chain> {
    /// Use for client certificate authentication
    pub identity: Option<Identity<'der, 'pass>>,
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

/// Holds PKCS#12 DER-encoded identity and decryption password
#[derive(Debug, PartialEq)]
pub struct Identity<'der, 'pass> {
    /// PKCS#12 DER-encoded identity
    pub der: &'der [u8],
    /// Decryption password
    pub password: &'pass str,
}

/// Holds PKCS#12 DER-encoded identity and decryption password
#[derive(Debug, PartialEq)]
pub struct OwnedIdentity {
    /// PKCS#12 DER-encoded identity
    pub der: Vec<u8>,
    /// Decryption password
    pub password: String,
}

impl OwnedIdentity {
    /// Get the ephemeral `Identity` corresponding to the `OwnedIdentity`
    #[must_use]
    pub fn as_ref(&self) -> Identity<'_, '_> {
        Identity {
            der: &self.der,
            password: &self.password,
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

    /// Check whether the stream is connected or not
    #[must_use]
    pub fn is_connected(&self) -> bool {
        if let Self::Plain(_, connected) = self {
            *connected
        } else {
            true
        }
    }

    /// Retry the connection. Returns:
    /// - Ok(true) if connected
    /// - Ok(false) if connecting
    /// - Err(_) if an error is encountered
    pub fn try_connect(&mut self) -> io::Result<bool> {
        if self.is_connected() {
            return Ok(true);
        }
        match self.is_writable() {
            Ok(()) => {
                if let Self::Plain(_, ref mut connected) = self {
                    *connected = true;
                }
                Ok(true)
            }
            Err(err)
                if [io::ErrorKind::WouldBlock, io::ErrorKind::NotConnected]
                    .contains(&err.kind()) =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
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
        connector: &OpenSslConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "rustls-connector")]
    /// Enable TLS using rustls
    pub fn into_rustls(
        self,
        connector: &RustlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[allow(irrefutable_let_patterns)]
    fn into_plain(self) -> Result<TcpStream, io::Error> {
        if let TcpStream::Plain(plain, connected) = self {
            Ok(TcpStream::Plain(plain, connected))
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

fn connect_std_raw<A: ToSocketAddrs>(addr: A, timeout: Option<Duration>) -> io::Result<StdTcpStream> {
    let mut addrs = addr.to_socket_addrs()?;
    let mut err = None;
    if let Some(timeout) = timeout {
        if let Some(addr) = addrs.next() {
            match StdTcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok(stream),
                Err(error) => err = Some(error),
            }
        }
    }
    for addr in addrs {
        match StdTcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(error) => err = Some(error),
        }
    }
    Err(err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "couldn't resolve host")
    }))
}

#[cfg(feature = "rustls-common")]
fn into_rustls_common(
    s: TcpStream,
    mut c: RustlsConnectorConfig,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    use rustls_connector::rustls::{Certificate, PrivateKey};

    if let Some(cert_chain) = config.cert_chain {
        let mut cert_chain = std::io::BufReader::new(cert_chain.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_chain)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        c.add_parsable_certificates(&certs);
    }
    let connector = if let Some(identity) = config.identity {
        let pfx = p12::PFX::parse(identity.der).map_err(io::Error::from)?;
        let key = if let Some(key) = pfx
            .key_bags(identity.password)
            .map_err(io::Error::from)?
            .get(0)
        {
            PrivateKey(key.clone())
        } else {
            return Err(
                io::Error::new(io::ErrorKind::Other, "No private key in pkcs12 DER").into(),
            );
        };
        let certs = pfx
            .cert_bags(identity.password)
            .map_err(io::Error::from)?
            .iter()
            .map(|cert| Certificate(cert.clone()))
            .collect();
        c.connector_with_single_cert(certs, key)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?
    } else {
        c.connector_with_no_client_auth()
    };
    s.into_rustls(&connector, domain)
}

cfg_if! {
    if #[cfg(feature = "rustls-native-certs")] {
        fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnectorConfig::new_with_native_certs()?, domain, config)
        }
    } else if #[cfg(feature = "rustls-webpki-roots-certs")] {
        fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnectorConfig::new_with_webpki_roots_certs(), domain, config)
        }
    } else if #[cfg(feature = "rustls-common")] {
        fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnectorConfig::default(), domain, config)
        }
    } else if #[cfg(feature = "openssl")] {
        fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            use openssl::x509::X509;

            let mut builder = OpenSslConnector::builder(OpenSslMethod::tls())?;
            if let Some(identity) = config.identity {
                let identity = openssl::pkcs12::Pkcs12::from_der(identity.der)?.parse(identity.password)?;
                builder.set_certificate(&identity.cert)?;
                builder.set_private_key(&identity.pkey)?;
                if let Some(chain) = identity.chain.as_ref() {
                    for cert in chain.iter().rev() {
                        builder.add_extra_chain_cert(cert.to_owned())?;
                    }
                }
            }
            if let Some(cert_chain) = config.cert_chain.as_ref() {
                for cert in X509::stack_from_pem(cert_chain.as_bytes())?.drain(..).rev() {
                    builder.cert_store_mut().add_cert(cert)?;
                }
            }
            s.into_openssl(&builder.build(), domain)
        }
    } else if #[cfg(feature = "native-tls")] {
        fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            use native_tls::Certificate;

            let mut builder = NativeTlsConnector::builder();
            if let Some(identity) = config.identity {
                builder.identity(native_tls::Identity::from_pkcs12(identity.der, identity.password).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?);
            }
            if let Some(cert_chain) = config.cert_chain {
                let mut cert_chain = std::io::BufReader::new(cert_chain.as_bytes());
                for cert in rustls_pemfile::read_all(&mut cert_chain)?.iter().rev() {
                    if let rustls_pemfile::Item::X509Certificate(cert) = cert {
                        builder.add_root_certificate(Certificate::from_der(&cert[..]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?);
                    }
                }
            }
            s.into_native_tls(&builder.build().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?, domain)
        }
    } else {
        fn into_tls_impl(s: TcpStream, _domain: &str, _: TLSConfig<'_, '_, '_>) -> HandshakeResult {
            Ok(s.into_plain()?)
        }
    }
}

impl TryFrom<StdTcpStream> for TcpStream {
    type Error = io::Error;

    fn try_from(s: StdTcpStream) -> io::Result<Self> {
        let mut this = TcpStream::Plain(s, false);
        this.try_connect()?;
        Ok(this)
    }
}

#[cfg(feature = "native-tls")]
impl From<NativeTlsStream> for TcpStream {
    fn from(s: NativeTlsStream) -> Self {
        TcpStream::NativeTls(Box::new(s))
    }
}

#[cfg(feature = "openssl")]
impl From<OpenSslStream> for TcpStream {
    fn from(s: OpenSslStream) -> Self {
        TcpStream::OpenSsl(Box::new(s))
    }
}

#[cfg(feature = "rustls-connector")]
impl From<RustlsStream> for TcpStream {
    fn from(s: RustlsStream) -> Self {
        TcpStream::Rustls(Box::new(s))
    }
}

impl TcpStream {
    /// Attempt reading from underlying stream, returning Ok(()) if the stream is readable
    pub fn is_readable(&self) -> io::Result<()> {
        self.deref().read(&mut []).map(|_| ())
    }

    /// Attempt writing to underlying stream, returning Ok(()) if the stream is writable
    pub fn is_writable(&self) -> io::Result<()> {
        self.deref().write(&[]).map(|_| ())
    }
}

impl Deref for TcpStream {
    type Target = StdTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            TcpStream::Plain(plain, _) => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_ref(),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(tls) => tls.get_ref(),
            #[cfg(feature = "rustls-connector")]
            TcpStream::Rustls(tls) => tls.get_ref(),
        }
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            TcpStream::Plain(plain, _) => plain,
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(tls) => tls.get_mut(),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(tls) => tls.get_mut(),
            #[cfg(feature = "rustls-connector")]
            TcpStream::Rustls(tls) => tls.get_mut(),
        }
    }
}

macro_rules! fwd_impl {
    ($self:ident, $method:ident, $($args:expr),*) => {
        match $self {
            TcpStream::Plain(ref mut plain, _) => plain.$method($($args),*),
            #[cfg(feature = "native-tls")]
            TcpStream::NativeTls(ref mut tls) => tls.$method($($args),*),
            #[cfg(feature = "openssl")]
            TcpStream::OpenSsl(ref mut tls) => tls.$method($($args),*),
            #[cfg(feature = "rustls-connector")]
            TcpStream::Rustls(ref mut tls) => tls.$method($($args),*),
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum MidHandshakeTlsStream {
    /// Not a TLS stream
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    /// A native-tls MidHandshakeTlsStream
    NativeTls(NativeTlsMidHandshakeTlsStream),
    #[cfg(feature = "openssl")]
    /// An openssl MidHandshakeTlsStream
    Openssl(OpenSslMidHandshakeTlsStream),
    #[cfg(feature = "rustls-connector")]
    /// A rustls-connector MidHandshakeTlsStream
    Rustls(RustlsMidHandshakeTlsStream),
}

impl MidHandshakeTlsStream {
    /// Get a reference to the inner stream
    #[must_use]
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            MidHandshakeTlsStream::Plain(mid) => mid,
            #[cfg(feature = "native-tls")]
            MidHandshakeTlsStream::NativeTls(mid) => mid.get_ref(),
            #[cfg(feature = "openssl")]
            MidHandshakeTlsStream::Openssl(mid) => mid.get_ref(),
            #[cfg(feature = "rustls-connector")]
            MidHandshakeTlsStream::Rustls(mid) => mid.get_ref(),
        }
    }

    /// Get a mutable reference to the inner stream
    #[must_use]
    pub fn get_mut(&mut self) -> &mut TcpStream {
        match self {
            MidHandshakeTlsStream::Plain(mid) => mid,
            #[cfg(feature = "native-tls")]
            MidHandshakeTlsStream::NativeTls(mid) => mid.get_mut(),
            #[cfg(feature = "openssl")]
            MidHandshakeTlsStream::Openssl(mid) => mid.get_mut(),
            #[cfg(feature = "rustls-connector")]
            MidHandshakeTlsStream::Rustls(mid) => mid.get_mut(),
        }
    }

    /// Retry the handshake
    pub fn handshake(self) -> HandshakeResult {
        Ok(match self {
            MidHandshakeTlsStream::Plain(mut mid) => {
                if !mid.try_connect()? {
                    return Err(HandshakeError::WouldBlock(mid.into()));
                }
                mid
            }
            #[cfg(feature = "native-tls")]
            MidHandshakeTlsStream::NativeTls(mut mid) => {
                if !mid.get_mut().try_connect()? {
                    return Err(HandshakeError::WouldBlock(mid.into()));
                }
                mid.handshake()?.into()
            }
            #[cfg(feature = "openssl")]
            MidHandshakeTlsStream::Openssl(mut mid) => {
                if !mid.get_mut().try_connect()? {
                    return Err(HandshakeError::WouldBlock(mid.into()));
                }
                mid.handshake()?.into()
            }
            #[cfg(feature = "rustls-connector")]
            MidHandshakeTlsStream::Rustls(mut mid) => {
                if !mid.get_mut().try_connect()? {
                    return Err(HandshakeError::WouldBlock(mid.into()));
                }
                mid.handshake()?.into()
            }
        })
    }
}

impl From<TcpStream> for MidHandshakeTlsStream {
    fn from(mid: TcpStream) -> Self {
        MidHandshakeTlsStream::Plain(mid)
    }
}

#[cfg(feature = "native-tls")]
impl From<NativeTlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: NativeTlsMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::NativeTls(mid)
    }
}

#[cfg(feature = "openssl")]
impl From<OpenSslMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: OpenSslMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::Openssl(mid)
    }
}

#[cfg(feature = "rustls-connector")]
impl From<RustlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: RustlsMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::Rustls(mid)
    }
}

impl fmt::Display for MidHandshakeTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MidHandshakeTlsStream")
    }
}

/// An error returned while performing the handshake
#[allow(clippy::large_enum_variant)]
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
            HandshakeError::WouldBlock(_) => f.write_str("WouldBlock hit during handshake"),
            HandshakeError::Failure(err) => f.write_fmt(format_args!("IO error: {}", err)),
        }
    }
}

impl Error for HandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Failure(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(feature = "native-tls")]
impl From<NativeTlsHandshakeError> for HandshakeError {
    fn from(error: NativeTlsHandshakeError) -> Self {
        match error {
            native_tls::HandshakeError::WouldBlock(mid) => HandshakeError::WouldBlock(mid.into()),
            native_tls::HandshakeError::Failure(failure) => {
                HandshakeError::Failure(io::Error::new(io::ErrorKind::Other, failure))
            }
        }
    }
}

#[cfg(feature = "openssl")]
impl From<OpenSslHandshakeError> for HandshakeError {
    fn from(error: OpenSslHandshakeError) -> Self {
        match error {
            openssl::ssl::HandshakeError::WouldBlock(mid) => HandshakeError::WouldBlock(mid.into()),
            openssl::ssl::HandshakeError::Failure(failure) => {
                HandshakeError::Failure(io::Error::new(io::ErrorKind::Other, failure.into_error()))
            }
            openssl::ssl::HandshakeError::SetupFailure(failure) => failure.into(),
        }
    }
}

#[cfg(feature = "openssl")]
impl From<OpenSslErrorStack> for HandshakeError {
    fn from(error: OpenSslErrorStack) -> Self {
        Self::Failure(error.into())
    }
}

#[cfg(feature = "rustls-connector")]
impl From<RustlsHandshakeError> for HandshakeError {
    fn from(error: RustlsHandshakeError) -> Self {
        match error {
            rustls_connector::HandshakeError::WouldBlock(mid) => {
                HandshakeError::WouldBlock(mid.into())
            }
            rustls_connector::HandshakeError::Failure(failure) => HandshakeError::Failure(failure),
        }
    }
}

impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> Self {
        HandshakeError::Failure(err)
    }
}

#[cfg(unix)]
mod sys {
    use crate::TcpStream;
    use std::{
        net::TcpStream as StdTcpStream,
        os::unix::io::{AsRawFd, FromRawFd, RawFd},
    };

    impl AsRawFd for TcpStream {
        fn as_raw_fd(&self) -> RawFd {
            <StdTcpStream as AsRawFd>::as_raw_fd(self)
        }
    }

    impl AsRawFd for &TcpStream {
        fn as_raw_fd(&self) -> RawFd {
            <StdTcpStream as AsRawFd>::as_raw_fd(self)
        }
    }

    impl FromRawFd for TcpStream {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Self::Plain(StdTcpStream::from_raw_fd(fd), false)
        }
    }
}

#[cfg(windows)]
mod sys {
    use crate::TcpStream;
    use std::{
        net::TcpStream as StdTcpStream,
        os::windows::io::{AsRawSocket, FromRawSocket, RawSocket},
    };

    impl AsRawSocket for TcpStream {
        fn as_raw_socket(&self) -> RawSocket {
            <StdTcpStream as AsRawSocket>::as_raw_socket(self)
        }
    }

    impl AsRawSocket for &TcpStream {
        fn as_raw_socket(&self) -> RawSocket {
            <StdTcpStream as AsRawSocket>::as_raw_socket(self)
        }
    }

    impl FromRawSocket for TcpStream {
        unsafe fn from_raw_socket(socket: RawSocket) -> Self {
            Self::Plain(StdTcpStream::from_raw_socket(socket), false)
        }
    }
}
