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

use std::{
    fmt,
    io::{self, Read, Write},
    net::{self, SocketAddr},
    ops::{Deref, DerefMut},
};

/// Wrapper around mio's TcpStream
pub enum TcpStream {
    /// Wrapper around mio's TcpStream
    Plain(MioTcpStream),
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
}

impl From<MioTcpStream> for TcpStream {
    fn from(s: MioTcpStream) -> Self {
        TcpStream::Plain(s)
    }
}

impl Deref for TcpStream {
    type Target = MioTcpStream;

    fn deref(&self) -> &Self::Target {
        match self {
            TcpStream::Plain(plain) => plain,
        }
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            TcpStream::Plain(plain) => plain,
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain) => plain.read(buf),
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TcpStream::Plain(ref mut plain) => plain.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TcpStream::Plain(ref mut plain) => plain.flush(),
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
