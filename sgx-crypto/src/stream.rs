use std::io::{Read, Write};

pub trait Stream: Read + Write {}
impl Stream for std::net::TcpStream {}
