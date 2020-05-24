use std::io::{Error, ErrorKind, Result};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::{Duration, Instant};

const CONNECT_SLEEP_TIME_MILLIS: u64 = 10;

pub fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let start = Instant::now();
    loop {
        match TcpStream::connect((host, port)) {
            Ok(s) => {
                return Ok(s);
            }
            Err(e) => {
                if start.elapsed() == timeout {
                    return Err(Error::new(ErrorKind::TimedOut, e));
                }
            }
        }
        sleep(Duration::from_millis(CONNECT_SLEEP_TIME_MILLIS));
    }
}

pub fn tcp_accept(port: u16) -> Result<TcpStream> {
    let listener = TcpListener::bind(("localhost", port))?;
    Ok(listener.accept()?.0)
}
