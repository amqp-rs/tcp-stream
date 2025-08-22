use crate::TLSConfig;

use async_rs::traits::*;
use cfg_if::cfg_if;
use futures_io::{AsyncRead, AsyncWrite};
use std::{
    io::{self, IoSlice, IoSliceMut},
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "native-tls-futures")]
use crate::{NativeTlsAsyncStream, NativeTlsConnectorBuilder};
#[cfg(feature = "openssl-futures")]
use crate::{OpensslAsyncStream, OpensslConnector};
#[cfg(feature = "rustls-futures")]
use crate::{RustlsAsyncStream, RustlsConnector, RustlsConnectorConfig};

/// Wrapper around plain or TLS async TCP streams
#[non_exhaustive]
pub enum AsyncTcpStream<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// Wrapper around plain async TCP stream
    Plain(S),
    #[cfg(feature = "native-tls-futures")]
    /// Wrapper around a TLS async stream hanled by native-tls
    NativeTls(NativeTlsAsyncStream<S>),
    #[cfg(feature = "openssl-futures")]
    /// Wrapper around a TLS async stream hanled by openssl
    Openssl(OpensslAsyncStream<S>),
    #[cfg(feature = "rustls-futures")]
    /// Wrapper around a TLS async stream hanled by rustls
    Rustls(RustlsAsyncStream<S>),
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncTcpStream<S> {
    /// Wrapper around `reactor_trait::TcpReactor::connect`
    pub async fn connect<
        R: Reactor<TcpStream = S> + Sync,
        A: AsyncToSocketAddrs + Send,
    >(
        reactor: &R,
        addr: A,
    ) -> io::Result<Self> {
        Ok(Self::Plain(reactor.tcp_connect(addr).await?))
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
        Ok(Self::NativeTls(
            async_native_tls::TlsConnector::from(connector)
                .connect(domain, self.into_plain()?)
                .await
                .map_err(io::Error::other)?,
        ))
    }

    #[cfg(feature = "openssl-futures")]
    /// Enable TLS using openssl
    pub async fn into_openssl(
        self,
        connector: &OpensslConnector,
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
        Ok(Self::Openssl(stream))
    }

    #[cfg(feature = "rustls-futures")]
    /// Enable TLS using rustls
    pub async fn into_rustls(self, connector: &RustlsConnector, domain: &str) -> io::Result<Self> {
        Ok(Self::Rustls(
            connector.connect_async(domain, self.into_plain()?).await?,
        ))
    }

    #[allow(irrefutable_let_patterns, dead_code)]
    fn into_plain(self) -> io::Result<S> {
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

async fn into_tls_impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    s: AsyncTcpStream<S>,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<AsyncTcpStream<S>> {
    cfg_if! {
        if #[cfg(all(feature = "rustls-futures", feature = "rustls-native-certs"))] {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::new_with_native_certs()?, domain, config).await
        } else if #[cfg(all(feature = "rustls-futures", feature = "rustls-webpki-roots-certs"))] {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::new_with_webpki_roots_certs(), domain, config).await
        } else if #[cfg(feature = "rustls-futures")] {
            crate::into_rustls_impl_async(s, RustlsConnectorConfig::default(), domain, config).await
        } else if #[cfg(feature = "openssl-futures")] {
            crate::into_openssl_impl_async(s, domain, config).await
        } else if #[cfg(feature = "native-tls-futures")] {
            crate::into_native_tls_impl_async(s, domain, config).await
        } else {
            let _ = (domain, config);
            Ok(AsyncTcpStream::Plain(s.into_plain()?))
        }
    }
}

macro_rules! fwd_impl {
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

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncRead for AsyncTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        fwd_impl!(self, poll_read, cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        fwd_impl!(self, poll_read_vectored, cx, bufs)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncWrite for AsyncTcpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        fwd_impl!(self, poll_write, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        fwd_impl!(self, poll_write_vectored, cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        fwd_impl!(self, poll_flush, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        fwd_impl!(self, poll_close, cx)
    }
}
