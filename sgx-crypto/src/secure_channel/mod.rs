pub mod encryption;
pub mod decryption;

use std::io::{Read, Write, Result};
use std::rc::Rc;
use std::cell::RefCell;
use self::encryption::*;
use self::decryption::*;

pub struct SecureChannel {
    w: EncryptedWriter,
    r: EncryptedReader,
}

impl SecureChannel {
    pub fn new(inner: impl Read + Write + 'static, key_bytes: &[u8; 16]) -> Self {
        Self::with_capacity(0x100000, inner, key_bytes)
    }

    pub fn with_capacity(capacity: usize, inner: impl Read + Write + 'static,
                         key_bytes: &[u8; 16]) -> Self {
        let inner = Rc::new(RefCell::new(inner));
        Self {
            w: EncryptedWriter::with_capacity(capacity, inner.clone(), key_bytes),
            r: EncryptedReader::with_capacity(capacity, inner.clone(), key_bytes),
        }
    }
}

impl Write for SecureChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.w.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.w.flush()
    }
}

impl Read for SecureChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.r.read(buf)
    }
}
