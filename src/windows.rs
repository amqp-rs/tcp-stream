use mio::net::TcpStream as MioTcpStream;

use crate::TcpStream;

use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};

impl AsRawSocket for TcpStream {
    fn as_raw_socket(&self) -> RawSocket {
        <MioTcpStream as AsRawSocket>::as_raw_socket(self)
    }
}

impl FromRawSocket for TcpStream {
    unsafe fn from_raw_socket(socket: RawSocket) -> Self {
        MioTcpStream::from_raw_socket(socket).into()
    }
}
