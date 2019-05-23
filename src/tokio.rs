use futures::Poll;
use tokio_io::{AsyncRead, AsyncWrite};

use crate::TcpStream;

use std::io;

impl AsyncRead for TcpStream {}

impl AsyncWrite for TcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(().into())
    }
}
