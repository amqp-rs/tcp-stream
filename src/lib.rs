#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/tcp-stream/0.11.0/")]

//! # mio's TCP stream on steroids
//!
//! tcp-stream is a library aiming at providing TLS and futures/tokio
//! support to mio's TcpStream without forcibly using tokio-reactor
//!
//! # Examples
//!
//! To connect to a remote server:
//!
//! ```rust
//! use tcp_stream::{HandshakeError, TcpStream};
//!
//! use std::io::{self, Read, Write};
//!
//! fn main() {
//!     let stream = TcpStream::connect("google.com:443").unwrap();
//!     let mut stream = stream.into_tls("google.com", None);
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
use mio::{event::Source, net::TcpStream as MioTcpStream, Interest, Registry, Token};

use std::{
    error::Error,
    fmt,
    io::{self, IoSlice, IoSliceMut, Read, Write},
    net::{self, ToSocketAddrs},
    ops::{Deref, DerefMut},
};

#[cfg(feature = "native-tls")]
/// Reexport native-tls's TlsConnector
pub use native_tls::TlsConnector as NativeTlsConnector;

#[cfg(feature = "native-tls")]
/// A TcpStream wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<MioTcpStream>;

#[cfg(feature = "native-tls")]
/// A MidHandshakeTlsStream from native-tls
pub type NativeTlsMidHandshakeTlsStream = native_tls::MidHandshakeTlsStream<MioTcpStream>;

#[cfg(feature = "native-tls")]
/// A HandshakeError from native-tls
pub type NativeTlsHandshakeError = native_tls::HandshakeError<MioTcpStream>;

#[cfg(feature = "openssl")]
/// Reexport openssl's TlsConnector
pub use openssl::ssl::{SslConnector as OpenSslConnector, SslMethod as OpenSslMethod};

#[cfg(feature = "openssl")]
/// A TcpStream wrapped by openssl
pub type OpenSslStream = openssl::ssl::SslStream<MioTcpStream>;

#[cfg(feature = "openssl")]
/// A MidHandshakeTlsStream from openssl
pub type OpenSslMidHandshakeTlsStream = openssl::ssl::MidHandshakeSslStream<MioTcpStream>;

#[cfg(feature = "openssl")]
/// A HandshakeError from openssl
pub type OpenSslHandshakeError = openssl::ssl::HandshakeError<MioTcpStream>;

#[cfg(feature = "openssl")]
/// An ErrorStack from openssl
pub type OpenSslErrorStack = openssl::error::ErrorStack;

#[cfg(feature = "rustls-connector")]
/// Reexport rustls-connector's TlsConnector
pub use rustls_connector::RustlsConnector;

#[cfg(feature = "rustls-connector")]
/// A TcpStream wrapped by rustls
pub type RustlsStream = rustls_connector::TlsStream<MioTcpStream>;

#[cfg(feature = "rustls-connector")]
/// A MidHandshakeTlsStream from rustls_connector
pub type RustlsMidHandshakeTlsStream = rustls_connector::MidHandshakeTlsStream<MioTcpStream>;

#[cfg(feature = "rustls-connector")]
/// A HandshakeError from rustls_connector
pub type RustlsHandshakeError = rustls_connector::HandshakeError<MioTcpStream>;

/// Wrapper around plain or TLS TCP streams
#[allow(clippy::large_enum_variant)]
pub enum TcpStream {
    /// Wrapper around mio's TcpStream
    Plain(MioTcpStream),
    #[cfg(feature = "native-tls")]
    /// Wrapper around a TLS stream hanled by native-tls
    NativeTls(NativeTlsStream),
    #[cfg(feature = "openssl")]
    /// Wrapper around a TLS stream hanled by openssl
    OpenSsl(OpenSslStream),
    #[cfg(feature = "rustls-connector")]
    /// Wrapper around a TLS stream hanled by rustls
    Rustls(RustlsStream),
}

/// Holds PKCS#12 DER-encoded identity and decryption password
#[derive(Debug, PartialEq)]
pub struct Identity<'a, 'b> {
    /// PKCS#12 DER-encoded identity
    pub der: &'a [u8],
    /// Decryption password
    pub password: &'b str,
}

/// Holds either the TLS TcpStream result or the current handshake state
pub type HandshakeResult = Result<TcpStream, HandshakeError>;

impl TcpStream {
    /// Wrapper around mio's TcpStream::connect inspired by std::net::TcpStream::connect
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let addrs = addr.to_socket_addrs()?;
        let mut err = None;
        for addr in addrs {
            match MioTcpStream::connect(addr) {
                Ok(stream) => return Ok(stream.into()),
                Err(error) => err = Some(error),
            }
        }
        Err(err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "couldn't resolve host")
        }))
    }

    /// Wrapper around mio's TcpStream::from_std
    pub fn from_std(stream: net::TcpStream) -> Self {
        MioTcpStream::from_std(stream).into()
    }

    /// Enable TLS
    pub fn into_tls(
        self,
        domain: &str,
        identity: Option<Identity<'_, '_>>,
    ) -> Result<Self, HandshakeError> {
        into_tls_impl(self, domain, identity)
    }

    #[cfg(feature = "native-tls")]
    /// Enable TLS using native-tls
    pub fn into_native_tls(
        self,
        connector: NativeTlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "openssl")]
    /// Enable TLS using openssl
    pub fn into_openssl(
        self,
        connector: OpenSslConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "rustls-connector")]
    /// Enable TLS using rustls
    pub fn into_rustls(
        self,
        connector: RustlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[allow(irrefutable_let_patterns)]
    fn into_plain(self) -> Result<MioTcpStream, io::Error> {
        if let TcpStream::Plain(plain) = self {
            Ok(plain)
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "already a TLS stream",
            ))
        }
    }
}

#[cfg(feature = "rustls-connector")]
fn into_rustls_common(
    s: TcpStream,
    c: RustlsConnector,
    domain: &str,
    _: Option<Identity<'_, '_>>,
) -> HandshakeResult {
    // FIXME: identity
    s.into_rustls(c, domain)
}

cfg_if! {
    if #[cfg(feature = "rustls-native-certs")] {
        fn into_tls_impl(s: TcpStream, domain: &str, identity: Option<Identity<'_, '_>>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnector::new_with_native_certs()?, domain, identity)
        }
    } else if #[cfg(feature = "rustls-webpki-roots-certs")] {
        fn into_tls_impl(s: TcpStream, domain: &str, identity: Option<Identity<'_, '_>>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnector::new_with_webpki_roots_certs(), domain, identity)
        }
    } else if #[cfg(feature = "rustls-connector")] {
        fn into_tls_impl(s: TcpStream, domain: &str, identity: Option<Identity<'_, '_>>) -> HandshakeResult {
            into_rustls_common(s, RustlsConnector::default(), domain, identity)
        }
    } else if #[cfg(feature = "openssl")] {
        fn into_tls_impl(s: TcpStream, domain: &str, identity: Option<Identity<'_, '_>>) -> HandshakeResult {
            let mut builder = OpenSslConnector::builder(OpenSslMethod::tls())?;
            if let Some(identity) = identity {
                let identity = openssl::pkcs12::Pkcs12::from_der(identity.der)?.parse(identity.password)?;
                builder.set_certificate(&identity.cert)?;
                builder.set_private_key(&identity.pkey)?;
                if let Some(chain) = identity.chain.as_ref() {
                    for cert in chain.iter().rev() {
                        builder.add_extra_chain_cert(cert.to_owned())?;
                    }
                }
            }
            s.into_openssl(builder.build(), domain)
        }
    } else if #[cfg(feature = "native-tls")] {
        fn into_tls_impl(s: TcpStream, domain: &str, identity: Option<Identity<'_, '_>>) -> HandshakeResult {
            let mut builder = NativeTlsConnector::builder();
            if let Some(identity) = identity {
                builder.identity(native_tls::Identity::from_pkcs12(identity.der, identity.password).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?);
            }
            s.into_native_tls(builder.build().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?, domain)
        }
    } else {
        fn into_tls_impl(s: TcpStream, _domain: &str, _: Option<Identity<'_, '_>>) -> HandshakeResult {
            Ok(TcpStream::Plain(s.into_plain()?))
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

#[cfg(feature = "rustls-connector")]
impl From<RustlsStream> for TcpStream {
    fn from(s: RustlsStream) -> Self {
        TcpStream::Rustls(s)
    }
}

impl Deref for TcpStream {
    type Target = MioTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            TcpStream::Plain(plain) => plain,
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
            TcpStream::Plain(plain) => plain,
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
            TcpStream::Plain(ref mut plain) => plain.$method($($args),*),
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

impl Source for TcpStream {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        <MioTcpStream as Source>::register(self, registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        <MioTcpStream as Source>::reregister(self, registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        <MioTcpStream as Source>::deregister(self, registry)
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
    Plain(MioTcpStream),
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
    pub fn get_ref(&self) -> &MioTcpStream {
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
    pub fn get_mut(&mut self) -> &mut MioTcpStream {
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
            MidHandshakeTlsStream::Plain(mid) => TcpStream::Plain(mid),
            #[cfg(feature = "native-tls")]
            MidHandshakeTlsStream::NativeTls(mid) => mid.handshake()?.into(),
            #[cfg(feature = "openssl")]
            MidHandshakeTlsStream::Openssl(mid) => mid.handshake()?.into(),
            #[cfg(feature = "rustls-connector")]
            MidHandshakeTlsStream::Rustls(mid) => mid.handshake()?.into(),
        })
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
mod unix;
