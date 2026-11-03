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
//! flags. The `futures` feature provides `AsyncTcpStream` and its `futures-io`
//! traits; async TLS additionally requires a matching backend feature.
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
//! ## TLS backend (`rustls` is the default)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls` *(default)* | TLS via rustls |
//! | `native-tls` | TLS via the platform's native library |
//! | `openssl` | TLS via OpenSSL |
//!
//! When several backends are enabled, [`TcpStream::into_tls`] uses `rustls`, then
//! `openssl`, then `native-tls`.
//!
//! ## Async TLS (`rustls-futures` is the default)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls-futures` *(default)* | Async TLS via rustls |
//! | `native-tls-futures` | Async TLS via native-tls |
//! | `openssl-futures` | Async TLS via OpenSSL |
//!
//! The `futures` feature alone only provides async I/O traits. The async
//! `into_tls()` follows the same priority. As rustls is enabled by default,
//! both `into_tls()` methods use another backend only when default features are
//! disabled.
//!
//! **Warning:** when no matching TLS backend is enabled, `into_tls()` deliberately
//! returns the plain stream without encryption and ignores its TLS configuration.
//! This allows downstream code to use the same call with and without TLS features.
//!
//! ## Rustls certificate store (only when `rustls` is active)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls-platform-verifier` *(default)* | Uses the platform trust store |
//! | `rustls-native-certs` | Loads native root certificates |
//! | `rustls-webpki-roots-certs` | Uses the webpki bundled root set |
//!
//! Enable a certificate store or supply custom roots through [`TLSConfig::cert_chain`].
//! With several store features enabled, rustls uses the first one listed above,
//! so another store needs default features disabled.
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
//! | `futures` | Enable the async stream wrapper and `futures-io` traits |
//! | `vendored-openssl` | Build a vendored OpenSSL (requires `openssl` feature) |
//!
//! # Example
//!
//! To connect to a remote server:
//!
//! ```no_run
//! use tcp_stream::{TcpStream, TLSConfig};
//!
//! use std::io::{Read, Write};
//!
//! let stream = TcpStream::connect("www.rust-lang.org:443").unwrap();
//! let mut stream = stream.into_tls("www.rust-lang.org", TLSConfig::default()).unwrap();
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! stream.flush().unwrap();
//!
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
//!
//! For nonblocking streams, wait for readiness between handshake retries. When
//! writing, use `write()` and keep the unsent suffix after each successful partial
//! write. Retrying an entire `write_all()` after `WouldBlock` can duplicate bytes
//! that were already sent.

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

#[cfg(any(feature = "rustls", feature = "native-tls", feature = "openssl"))]
mod pem;

#[cfg(feature = "native-tls")]
mod native_tls_impl;
#[cfg(feature = "native-tls")]
pub use native_tls_impl::*;

#[cfg(feature = "openssl")]
mod openssl_impl;
#[cfg(feature = "openssl")]
pub use openssl_impl::*;

/// The error kind that every backend reports for invalid identities and roots.
#[cfg(any(feature = "rustls", feature = "native-tls", feature = "openssl"))]
fn invalid_data(error: impl Into<Box<dyn Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(any(feature = "native-tls", feature = "openssl"))]
fn validate_domain(domain: &str) -> io::Result<()> {
    validate_no_nul(domain, "TLS domain contains a NUL byte")
}

#[cfg(any(feature = "native-tls", feature = "openssl"))]
fn validate_pkcs12_password(password: &str) -> io::Result<()> {
    validate_no_nul(password, "PKCS#12 password contains a NUL byte")
}

#[cfg(any(feature = "native-tls", feature = "openssl"))]
fn validate_no_nul(value: &str, message: &'static str) -> io::Result<()> {
    // These backends pass strings to C APIs. Upstream CString conversions can
    // panic and include the offending bytes, including identity passwords.
    if value.as_bytes().contains(&0) {
        Err(io::Error::new(io::ErrorKind::InvalidInput, message))
    } else {
        Ok(())
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
#[derive(Default, Debug, PartialEq)]
pub struct TLSConfig<'data, 'key, 'chain> {
    /// Use for client certificate authentication
    pub identity: Option<Identity<'data, 'key>>,
    /// Additional trusted root certificates in PEM format.
    /// Malformed certificates are rejected, and a chain without certificates
    /// adds no roots. `TRUSTED CERTIFICATE` objects are skipped.
    /// These roots extend the selected certificate store. On Android, the rustls
    /// platform verifier accepts no extra roots, so connecting fails when it is
    /// the selected store and the chain holds a certificate.
    pub cert_chain: Option<&'chain str>,
}

/// Holds extra TLS configuration
#[derive(Clone, Default, Debug, PartialEq)]
pub struct OwnedTLSConfig {
    /// Use for client certificate authentication
    pub identity: Option<OwnedIdentity>,
    /// Additional trusted root certificates in PEM format.
    /// Malformed certificates are rejected, and a chain without certificates
    /// adds no roots. `TRUSTED CERTIFICATE` objects are skipped.
    /// These roots extend the selected certificate store. On Android, the rustls
    /// platform verifier accepts no extra roots, so connecting fails when it is
    /// the selected store and the chain holds a certificate.
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
/// - PKCS#8 PEM-encoded certificate chain and key (without decryption password)
///
/// `Debug` output redacts all identity fields.
#[derive(PartialEq)]
pub enum Identity<'data, 'key> {
    /// PKCS#12 DER-encoded identity with decryption password
    PKCS12 {
        /// PKCS#12 DER-encoded identity
        der: &'data [u8],
        /// Decryption password
        ///
        /// Native TLS and OpenSSL reject embedded NUL bytes with `InvalidInput`.
        password: &'key str,
    },
    /// PKCS#8 PEM-encoded key with a PEM-encoded certificate chain.
    /// Use an unencrypted key; no decryption password is supplied or requested
    /// interactively.
    /// Native TLS validates the full key structure and imports only normalized
    /// PEM containing the validated key and certificates.
    /// Native TLS on Apple platforms other than macOS requires PKCS#12;
    /// configuring a PKCS#8 identity there returns `Unsupported`.
    PKCS8 {
        /// PEM-encoded certificate chain, leaf first
        pem: &'data [u8],
        /// PEM-encoded key
        key: &'key [u8],
    },
}

/// Holds one of:
/// - PKCS#12 DER-encoded identity and decryption password
/// - PKCS#8 PEM-encoded certificate chain and key (without decryption password)
///
/// `Debug` output redacts all identity fields.
#[derive(Clone, PartialEq)]
pub enum OwnedIdentity {
    /// PKCS#12 DER-encoded identity with decryption password
    PKCS12 {
        /// PKCS#12 DER-encoded identity
        der: Vec<u8>,
        /// Decryption password
        ///
        /// Native TLS and OpenSSL reject embedded NUL bytes with `InvalidInput`.
        password: String,
    },
    /// PKCS#8 PEM-encoded key with a PEM-encoded certificate chain.
    /// Use an unencrypted key; no decryption password is supplied or requested
    /// interactively.
    /// Native TLS validates the full key structure and imports only normalized
    /// PEM containing the validated key and certificates.
    /// Native TLS on Apple platforms other than macOS requires PKCS#12;
    /// configuring a PKCS#8 identity there returns `Unsupported`.
    PKCS8 {
        /// PEM-encoded certificate chain, leaf first
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

impl fmt::Debug for Identity<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PKCS12 { .. } => "PKCS12",
            Self::PKCS8 { .. } => "PKCS8",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}

impl fmt::Debug for OwnedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
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
    ///
    /// Each resolved address is tried in turn with the full timeout.
    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        connect_std(addr, Some(timeout)).and_then(Self::try_from)
    }

    /// Convert from a `std::net::TcpStream`
    pub fn from_std(stream: StdTcpStream) -> io::Result<Self> {
        Self::try_from(stream)
    }

    /// Check the underlying TCP socket without blocking or consuming data.
    ///
    /// Returns `Ok(())` if it is readable, including EOF, or `WouldBlock` if it
    /// is not. A pending socket error is returned once no data precedes it, as
    /// the next read would return it. Linux and Windows clear it then; other
    /// systems, such as macOS, keep it for that read.
    /// Readiness is a snapshot; a later read can still block. Queued error
    /// notifications, such as transmit timestamps, do not count as readable.
    /// Urgent data counts as readable only when `SO_OOBINLINE` is enabled. On
    /// Windows, a socket whose read side was shut down locally reports
    /// `WouldBlock`, although a read returns EOF.
    /// This checks raw socket readiness, including for TLS streams; it does not
    /// account for plaintext already buffered by the TLS backend. Targets without
    /// socket polling support use a zero-length read instead, which can block a
    /// blocking socket and report readiness without data.
    pub fn is_readable(&self) -> io::Result<()> {
        is_readable(self.deref())
    }

    /// Check the underlying TCP socket without blocking.
    ///
    /// Returns `Ok(())` if it is writable or `WouldBlock` if it is not. A pending
    /// socket error is returned, and retrieving it clears it, so a later read can
    /// then report EOF instead. Readiness is a snapshot; a later write can still
    /// block. This checks the raw socket, including for TLS streams, and returns
    /// `BrokenPipe` once the local side can no longer send; on Windows, a reset
    /// connection keeps returning its reset error instead. On a blocking TCP Fast
    /// Open socket that deferred its handshake, the check starts the handshake
    /// and waits for it. Targets without socket polling support use a zero-length
    /// write, which cannot detect a full send buffer.
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
    /// The TLS backend is selected by feature flag. When multiple backends are
    /// enabled, the priority is `rustls`, then `openssl`, then `native-tls`.
    /// `rustls` is a default feature, so selecting another backend here requires
    /// disabling defaults. Use `into_rustls`, `into_native_tls`, or
    /// `into_openssl` to target a specific backend explicitly.
    ///
    /// # Warning
    ///
    /// When no TLS backend feature is enabled, this deliberately returns the
    /// plain stream without encryption and ignores `domain` and `config`. This
    /// supports downstream code shared between TLS and plaintext builds.
    pub fn into_tls(
        self,
        domain: &str,
        config: TLSConfig<'_, '_, '_>,
    ) -> Result<Self, HandshakeError> {
        into_tls_impl(self, domain, config)
    }

    #[cfg(feature = "native-tls")]
    /// Enable TLS using native-tls
    ///
    /// A domain containing a NUL byte returns `InvalidInput`.
    pub fn into_native_tls(
        self,
        connector: &NativeTlsConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        validate_domain(domain)?;
        Ok(connector.connect(domain, self.into_plain()?)?.into())
    }

    #[cfg(feature = "openssl")]
    /// Enable TLS using openssl
    ///
    /// A domain containing a NUL byte returns `InvalidInput`.
    pub fn into_openssl(
        self,
        connector: &OpensslConnector,
        domain: &str,
    ) -> Result<Self, HandshakeError> {
        validate_domain(domain)?;
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

// The socket checks use rustix, which does not build on some Unix targets.
// Those keep zero-length probes, as do targets without rustix support.
cfg_if! {
    if #[cfg(any(
        all(
            unix,
            not(any(
                target_os = "nuttx",
                target_os = "qnx",
                target_os = "rtems",
                target_os = "vxworks"
            ))
        ),
        windows,
        target_os = "wasi"
    ))] {
        mod rustix_checks;
        use rustix_checks::{handshake_started, is_readable, is_writable, try_connect};
    } else {
        mod probe_checks;
        use probe_checks::{handshake_started, is_readable, is_writable, try_connect};
    }
}

/// Write zero bytes, which sends nothing but fails after a local write shutdown
/// or with a pending socket error. On a TCP Fast Open socket that deferred its
/// handshake, it starts the handshake, and waits for it on a blocking socket.
fn write_probe(mut stream: &StdTcpStream) -> io::Result<()> {
    let result = stream.write(&[]).map(drop);
    #[cfg(windows)]
    return result.map_err(shutdown_as_broken_pipe);
    #[cfg(not(windows))]
    result
}

/// Report the `WSAESHUTDOWN` of a local write shutdown as `BrokenPipe`, which
/// older standard libraries do not.
#[cfg(windows)]
fn shutdown_as_broken_pipe(err: io::Error) -> io::Error {
    const WSAESHUTDOWN: i32 = rustix::io::Errno::SHUTDOWN.raw_os_error();
    if err.raw_os_error() == Some(WSAESHUTDOWN) && err.kind() != io::ErrorKind::BrokenPipe {
        io::Error::new(io::ErrorKind::BrokenPipe, err)
    } else {
        err
    }
}

/// Check a connection with a zero-length write, which fails while it is
/// pending or after it failed. Use it only where the socket cannot be polled or
/// does not report its peer: it does not distinguish a full send buffer from a
/// pending connection.
fn probe_connection(stream: &StdTcpStream) -> io::Result<bool> {
    match write_probe(stream) {
        Ok(()) => Ok(true),
        Err(err) if connection_in_progress(&err) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Whether a write failed only because the connection is not established yet.
fn connection_in_progress(err: &io::Error) -> bool {
    handshake_started(err)
        || matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected
        )
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
            // Intentional plaintext fallback for code shared across feature sets.
            let _ = (domain, config);
            Ok(TcpStream::Plain(s.into_plain()?))
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
mod tests;
