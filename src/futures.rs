use crate::TLSConfig;

use cfg_if::cfg_if;
use futures_io::{AsyncRead, AsyncWrite};
use reactor_trait::{AsyncIOHandle, AsyncToSocketAddrs, TcpReactor};
use std::{
    io::{self, IoSlice, IoSliceMut},
    pin::{Pin, pin},
    task::{Context, Poll},
};

#[cfg(feature = "native-tls-futures")]
use crate::NativeTlsConnectorBuilder;
#[cfg(feature = "openssl-futures")]
use crate::OpenSslConnector;
#[cfg(feature = "rustls-futures")]
use crate::{RustlsConnector, RustlsConnectorConfig};

type AsyncStream = Pin<Box<dyn AsyncIOHandle + Send>>;

/// Wrapper around plain or TLS async TCP streams
pub enum AsyncTcpStream {
    /// Wrapper around plain async TCP stream
    Plain(AsyncStream),
    /// Wrapper around a TLS async TCP stream
    TLS(AsyncStream),
}

impl AsyncTcpStream {
    /// Wrapper around `reactor_trait::TcpReactor::connect`
    pub async fn connect<R: TcpReactor, A: AsyncToSocketAddrs>(
        reactor: R,
        addr: A,
    ) -> io::Result<Self> {
        let addrs = addr.to_socket_addrs().await?;
        let mut err = None;
        for addr in addrs {
            match reactor.connect(addr).await {
                Ok(stream) => return Ok(Self::Plain(stream.into())),
                Err(e) => err = Some(e),
            }
        }
        Err(err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "couldn't resolve host")
        }))
    }

    /// Enable TLS
    pub async fn into_tls(self, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<Self> {
        into_tls_impl(self, domain, config).await
    }

    #[cfg(feature = "native-tls-futures")]
    /// Enable TLS using native-tls
    pub async fn into_native_tls(
        self,
        connector: NativeTlsConnectorBuilder,
        domain: &str,
    ) -> io::Result<Self> {
        Ok(Self::TLS(Box::pin(
            async_native_tls::TlsConnector::from(connector)
                .connect(domain, self.into_plain()?)
                .await
                .map_err(io::Error::other)?,
        )))
    }

    #[cfg(feature = "openssl-futures")]
    /// Enable TLS using openssl
    pub async fn into_openssl(
        self,
        connector: &OpenSslConnector,
        domain: &str,
    ) -> io::Result<Self> {
        let mut stream = async_openssl::SslStream::new(
            connector.configure()?.into_ssl(domain)?,
            self.into_plain()?,
        )?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(io::Error::other)?;
        Ok(Self::TLS(Box::pin(stream)))
    }

    #[cfg(feature = "rustls-futures")]
    /// Enable TLS using rustls
    pub async fn into_rustls(self, connector: &RustlsConnector, domain: &str) -> io::Result<Self> {
        Ok(Self::TLS(Box::pin(
            connector.connect_async(domain, self.into_plain()?).await?,
        )))
    }

    #[allow(irrefutable_let_patterns, dead_code)]
    fn into_plain(self) -> io::Result<AsyncStream> {
        if let AsyncTcpStream::Plain(plain) = self {
            Ok(plain)
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "already a TLS stream",
            ))
        }
    }
}

cfg_if! {
    if #[cfg(all(feature = "rustls-futures", feature = "rustls-native-certs"))] {
        async fn into_tls_impl(s: AsyncTcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::new_with_native_certs()?, domain, config).await
        }
    } else if #[cfg(all(feature = "rustls-futures", feature = "rustls-webpki-roots-certs"))] {
        async fn into_tls_impl(s: AsyncTcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::new_with_webpki_roots_certs(), domain, config).await
        }
    } else if #[cfg(feature = "rustls-futures")] {
        async fn into_tls_impl(s: AsyncTcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::default(), domain, config).await
        }
    } else if #[cfg(feature = "openssl-futures")] {
        async fn into_tls_impl(s: AsyncTcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            crate::into_openssl_impl_async(s, domain, config).await
        }
    } else if #[cfg(feature = "native-tls-futures")] {
        async fn into_tls_impl(s: AsyncTcpStream, domain: &str, config: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            crate::into_native_tls_impl_async(s, domain, config).await
        }
    } else {
        async fn into_tls_impl(s: AsyncTcpStream, _domain: &str, _: TLSConfig<'_, '_, '_>) -> io::Result<AsyncTcpStream> {
            Ok(AsyncTcpStream::Plain(s.into_plain()?))
        }
    }
}

impl AsyncRead for AsyncTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_read(cx, buf),
            Self::TLS(tls) => pin!(tls).poll_read(cx, buf),
        }
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_read_vectored(cx, bufs),
            Self::TLS(tls) => pin!(tls).poll_read_vectored(cx, bufs),
        }
    }
}

impl AsyncWrite for AsyncTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_write(cx, buf),
            Self::TLS(tls) => pin!(tls).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_write_vectored(cx, bufs),
            Self::TLS(tls) => pin!(tls).poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_flush(cx),
            Self::TLS(tls) => pin!(tls).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(plain) => pin!(plain).poll_close(cx),
            Self::TLS(tls) => pin!(tls).poll_close(cx),
        }
    }
}
