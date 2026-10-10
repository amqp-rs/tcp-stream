#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![warn(unreachable_pub, unused_qualifications, unused_lifetimes)]
#![warn(
    clippy::must_use_candidate,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn
)]
#![allow(clippy::large_enum_variant, clippy::result_large_err)]

//! A [`TcpStream`] with pluggable TLS support.
//!
//! Wraps `std::net::TcpStream` in a [`TcpStream`] enum that can be upgraded
//! to a TLS-encrypted stream via [`TcpStream::into_tls`]. Supported backends
//! are rustls (default), native-tls, and OpenSSL, selected through feature
//! flags. Async variants of the encrypted stream are provided via the
//! `futures-io` traits when the `futures` feature is enabled.
//!
//! # Feature flags
//!
//! ## Async runtime (pick exactly one)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `tokio` *(default)* | Requires a running Tokio runtime |
//! | `smol` | Uses the smol executor |
//! | `async-global-executor` | Uses async-global-executor |
//!
//! ## TLS backend (pick at most one; `rustls` is the default)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls` *(default)* | TLS via rustls |
//! | `native-tls` | TLS via the platform's native library |
//! | `openssl` | TLS via OpenSSL |
//!
//! ## Rustls certificate store (only when `rustls` is active)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls-platform-verifier` *(default)* | Uses the platform trust store |
//! | `rustls-native-certs` | Loads native root certificates |
//! | `rustls-webpki-roots-certs` | Uses the webpki bundled root set |
//!
//! ## Rustls crypto provider (at least one must be enabled)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs |
//! | `rustls--ring` | Uses ring (more portable) |
//!
//! ## Miscellaneous
//!
//! | Flag | Notes |
//! |------|-------|
//! | `futures` | Enable `futures-io` async trait impls on the encrypted stream |
//! | `vendored-openssl` | Build a vendored OpenSSL (requires `openssl` feature) |
//!
//! # Example
//!
//! To connect to a remote server:
//!
//! This example is compiled but not run: it needs network access, and which
//! TLS backend (if any) is available depends on the enabled features. See the
//! crate's test suite for runnable equivalents.
//!
//! ```rust,no_run
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
//! // On a non-blocking stream a write can report `WouldBlock` after having
//! // already written part of the buffer, so track the offset rather than
//! // retrying `write_all` with the whole buffer (which would resend the
//! // prefix that already made it out).
//! let request = b"GET / HTTP/1.0\r\n\r\n";
//! let mut written = 0;
//! while written < request.len() {
//!     match stream.write(&request[written..]) {
//!         Ok(0) => panic!("connection closed by peer"),
//!         Ok(n) => written += n,
//!         Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
//!         Err(err) => panic!("error: {:?}", err),
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

#[cfg(feature = "futures")]
macro_rules! fwd_pin_impl {
    ($self:ident, $method:ident, $($args:expr),*) => {
        match $self.get_mut() {
            Self::Plain(plain) => Pin::new(plain).$method($($args),*),
            #[cfg(feature = "native-tls-futures")]
            Self::NativeTls(tls) => Pin::new(tls).$method($($args),*),
            #[cfg(feature = "openssl-futures")]
            Self::Openssl(tls) => Pin::new(tls).$method($($args),*),
            #[cfg(feature = "rustls-futures")]
            Self::Rustls(tls) => Pin::new(tls).$method($($args),*),
        }
    };
}

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
    /// Wrapper around a TLS stream handled by native-tls
    NativeTls(NativeTlsStream),
    #[cfg(feature = "openssl")]
    /// Wrapper around a TLS stream handled by openssl
    Openssl(OpensslStream),
    #[cfg(feature = "rustls")]
    /// Wrapper around a TLS stream handled by rustls
    Rustls(RustlsStream),
}

/// Holds extra TLS configuration
///
/// The `Debug` implementation of [`Identity`] redacts secrets, so logging a
/// `TLSConfig` will not expose a private key or a PKCS#12 password.
#[derive(Default, Debug, PartialEq)]
pub struct TLSConfig<'data, 'key, 'chain> {
    /// Use for client certificate authentication
    pub identity: Option<Identity<'data, 'key>>,
    /// Extra trusted certificates in PEM format
    ///
    /// These are **added to** the trust store the selected backend already
    /// uses (the platform or webpki roots); they do not replace it. All
    /// certificates found in the PEM blob are added.
    pub cert_chain: Option<&'chain str>,
}

/// Holds extra TLS configuration
///
/// The `Debug` implementation of [`OwnedIdentity`] redacts secrets, so logging
/// an `OwnedTLSConfig` will not expose a private key or a PKCS#12 password.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct OwnedTLSConfig {
    /// Use for client certificate authentication
    pub identity: Option<OwnedIdentity>,
    /// Extra trusted certificates in PEM format
    ///
    /// These are **added to** the trust store the selected backend already
    /// uses (the platform or webpki roots); they do not replace it. All
    /// certificates found in the PEM blob are added.
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
///
/// The `Debug` implementation deliberately redacts every field so that key
/// material and passwords are never written to logs; only the variant and the
/// length of each field are reported.
#[derive(PartialEq)]
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
///
/// The `Debug` implementation deliberately redacts every field so that key
/// material and passwords are never written to logs; only the variant and the
/// length of each field are reported.
#[derive(Clone, PartialEq)]
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

/// Stands in for a secret in `Debug` output, reporting only its length.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("<redacted, {} bytes>", self.0))
    }
}

/// Formats an identity without ever revealing key material or passwords.
fn fmt_identity(f: &mut fmt::Formatter<'_>, identity: &Identity<'_, '_>) -> fmt::Result {
    match identity {
        Identity::PKCS12 { der, password } => f
            .debug_struct("PKCS12")
            .field("der", &Redacted(der.len()))
            .field("password", &Redacted(password.len()))
            .finish(),
        Identity::PKCS8 { pem, key } => f
            .debug_struct("PKCS8")
            .field("pem", &Redacted(pem.len()))
            .field("key", &Redacted(key.len()))
            .finish(),
    }
}

impl fmt::Debug for Identity<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_identity(f, self)
    }
}

impl fmt::Debug for OwnedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_identity(f, &self.as_ref())
    }
}

/// Holds either the TLS `TcpStream` result or the current handshake state
pub type HandshakeResult = Result<TcpStream, HandshakeError>;

impl TcpStream {
    /// Wrapper around `std::net::TcpStream::connect`
    ///
    /// Note that, like every other constructor of this type, this enables
    /// `TCP_NODELAY` on the resulting socket.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        connect_std(addr, None).and_then(Self::try_from)
    }

    /// Wrapper around `std::net::TcpStream::connect_timeout`
    ///
    /// Note that, like every other constructor of this type, this enables
    /// `TCP_NODELAY` on the resulting socket.
    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        connect_std(addr, Some(timeout)).and_then(Self::try_from)
    }

    /// Convert from a `std::net::TcpStream`
    ///
    /// Note that this enables `TCP_NODELAY` on the given socket, overriding
    /// whatever the caller may have configured.
    pub fn from_std(stream: StdTcpStream) -> io::Result<Self> {
        Self::try_from(stream)
    }

    /// Attempt reading from underlying stream, returning Ok(()) if the stream is readable
    pub fn is_readable(&self) -> io::Result<()> {
        self.deref().read(&mut []).map(|_| ())
    }

    /// Attempt writing to underlying stream, returning Ok(()) if the stream is writable
    pub fn is_writable(&self) -> io::Result<()> {
        is_writable(self.deref())
    }

    /// Retry the connection. Returns:
    /// - Ok(true) if connected
    /// - Ok(false) if connecting
    /// - Err(_) if an error is encountered
    pub fn try_connect(&mut self) -> io::Result<bool> {
        try_connect(self)
    }

    /// Upgrade this plain stream to TLS, returning either a completed [`TcpStream`] or a
    /// [`HandshakeError::WouldBlock`] mid-handshake value that can be retried.
    ///
    /// The TLS backend is selected by feature flag (rustls by default; native-tls or openssl
    /// as alternatives). Use [`into_rustls`](Self::into_rustls),
    /// `into_native_tls`, or `into_openssl` to
    /// target a specific backend explicitly.
    ///
    /// # Errors
    ///
    /// If the crate was built without any TLS backend feature, this fails with
    /// [`io::ErrorKind::Unsupported`] rather than silently handing back an
    /// unencrypted stream.
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

    // `dead_code`: unused when the crate is built without any TLS backend.
    #[allow(irrefutable_let_patterns, dead_code)]
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
    if let Some(timeout) = timeout {
        let addrs = addr.to_socket_addrs()?;
        let mut err = None;
        for addr in addrs {
            match StdTcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok(stream),
                // Keep the last failure, which is what `std::net::TcpStream`
                // reports when it walks several addresses itself. The
                // timeout-free branch below delegates straight to std, so
                // matching it keeps the two paths consistent.
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

fn is_writable(mut stream: &StdTcpStream) -> io::Result<()> {
    stream.write(&[]).map(|_| ())
}

fn into_tls_impl(s: TcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> HandshakeResult {
    cfg_if! {
        if #[cfg(feature = "rustls")] {
            into_rustls_impl(s, domain, config)
        } else if #[cfg(feature = "openssl")] {
            into_openssl_impl(s, domain, config)
        } else if #[cfg(feature = "native-tls")] {
            into_native_tls_impl(s, domain, config)
        } else {
            let _ = (s, domain, config);
            // Returning the plain stream here would silently downgrade a
            // connection the caller asked to encrypt, so refuse instead.
            Err(HandshakeError::Failure(io::Error::new(
                io::ErrorKind::Unsupported,
                "no TLS backend enabled: build tcp-stream with one of the \
                 `rustls`, `openssl` or `native-tls` features",
            )))
        }
    }
}

impl TryFrom<StdTcpStream> for TcpStream {
    type Error = io::Error;

    fn try_from(s: StdTcpStream) -> io::Result<Self> {
        s.set_nodelay(true)?;
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
#[non_exhaustive]
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

    /// Retry a non-blocking TLS handshake that previously returned [`HandshakeError::WouldBlock`].
    ///
    /// Returns the completed [`TcpStream`] on success, or a new [`HandshakeError`] if the
    /// handshake would block again or fails permanently.
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
#[non_exhaustive]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Serves one connection, echoing everything back.
    fn echo_server() -> io::Result<(std::net::SocketAddr, std::thread::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0; 64];
                while let Ok(read) = socket.read(&mut buf) {
                    if read == 0 || socket.write_all(&buf[..read]).is_err() {
                        break;
                    }
                }
            }
        });
        Ok((addr, handle))
    }

    #[test]
    fn plain_stream_round_trip() {
        let (addr, server) = echo_server().unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        assert!(stream.is_writable().is_ok());
        assert!(stream.try_connect().unwrap());

        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn constructors_enable_nodelay() {
        let (addr, server) = echo_server().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        assert!(stream.nodelay().unwrap());
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn into_plain_unwraps_a_plain_stream() {
        let (addr, server) = echo_server().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        assert!(stream.into_plain().is_ok());
        server.join().unwrap();
    }

    #[test]
    fn identity_debug_redacts_secrets() {
        const PASSWORD: &str = "correct-horse-battery-staple";
        const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----aaaa-----END PRIVATE KEY-----";

        let pkcs12 = TLSConfig {
            identity: Some(Identity::PKCS12 {
                der: b"pkcs12-bundle",
                password: PASSWORD,
            }),
            cert_chain: None,
        };
        let rendered = format!("{pkcs12:?}");
        assert!(
            !rendered.contains(PASSWORD),
            "password leaked into Debug output: {rendered}",
        );
        assert!(rendered.contains("<redacted, 28 bytes>"), "{rendered}");

        let pkcs8 = OwnedTLSConfig {
            identity: Some(OwnedIdentity::PKCS8 {
                pem: b"certificate".to_vec(),
                key: KEY.to_vec(),
            }),
            cert_chain: None,
        };
        let rendered = format!("{pkcs8:?}");
        for byte in KEY.windows(8) {
            assert!(
                !rendered.contains(&String::from_utf8_lossy(byte).to_string()),
                "key material leaked into Debug output: {rendered}",
            );
        }
        assert!(rendered.contains("<redacted, 56 bytes>"), "{rendered}");
    }

    /// Without a TLS backend, `into_tls` must refuse rather than quietly hand
    /// back an unencrypted stream.
    #[test]
    #[cfg(not(any(feature = "rustls", feature = "openssl", feature = "native-tls")))]
    fn into_tls_without_a_backend_is_unsupported() {
        let (addr, server) = echo_server().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let err = match stream.into_tls("localhost", TLSConfig::default()) {
            Err(HandshakeError::Failure(err)) => err,
            Ok(_) => panic!("into_tls silently returned an unencrypted stream"),
            Err(err) => panic!("unexpected error: {err:?}"),
        };
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        server.join().unwrap();
    }
}
