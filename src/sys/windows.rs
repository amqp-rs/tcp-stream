use crate::TcpStream;
use std::{
    net::TcpStream as StdTcpStream,
    os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, FromRawSocket, RawSocket},
};

impl AsSocket for TcpStream {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        <StdTcpStream as AsSocket>::as_socket(self)
    }
}

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
        Self::Plain(unsafe { StdTcpStream::from_raw_socket(socket) })
    }
}
