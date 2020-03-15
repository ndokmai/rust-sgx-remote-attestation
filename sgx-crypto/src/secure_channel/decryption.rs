use std::io::{Result, Read, Error, ErrorKind};
use std::rc::Rc;
use std::cell::RefCell;
use ring::aead::{OpeningKey, open_in_place, AES_128_GCM, Aad, Nonce};
use byteorder::{ReadBytesExt, NetworkEndian};

pub struct EncryptedReader {
    inner: Rc<RefCell<dyn Read>>,
    buf: Vec<u8>,
    seq: u64,
    cursor: usize, 
    key: OpeningKey,
    tag_len: usize,
}

impl EncryptedReader {
    pub fn with_capacity(capacity: usize, inner: Rc<RefCell<dyn Read>>, 
                         key_bytes: &[u8]) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity + AES_128_GCM.tag_len()),
            seq: 0,
            cursor: 0,
            key: OpeningKey::new(&AES_128_GCM, key_bytes).unwrap(),
            tag_len: AES_128_GCM.tag_len(),
        }
    }

    fn fill_buf(&mut self) -> Result<()>{
        assert!(self.buf.is_empty());
        let r = self.inner.borrow_mut().read_u32::<NetworkEndian>();
        let len: usize = match r {
            Ok(n) if n as usize > self.buf.capacity() => {
                return Err(Error::new(ErrorKind::InvalidInput,
                                      "Input too large"));
            }
            Ok(n) => n as usize, 
            Err(e) => return Err(e),
        };
        self.buf.resize(len, 0);

        let mut nonce = [0u8; 12];
        let mut read = 0;
        while read < nonce.len() {
            let r = self.inner.borrow_mut().read(&mut nonce[read..]);
            match r {
                Ok(0) => {
                    return Err(Error::new(ErrorKind::UnexpectedEof,
                                          "Failed to read"));
                }
                Ok(n) => read += n,
                Err(e) => { return Err(e); }
            }
        }

        let mut read = 0;
        while read < len {
            let r = self.inner.borrow_mut().read(&mut self.buf[read..]);
            match r {
                Ok(0) => {
                    return Err(Error::new(ErrorKind::UnexpectedEof,
                                          "Failed to read"));
                }
                Ok(n) => read += n,
                Err(e) => { return Err(e); }
            }
        }

        decrypt(&self.key, &nonce, &mut self.buf[..])?;
        self.buf.resize(len-self.tag_len, 0);

        self.cursor = 0;
        Ok(())
    }
}

impl Read for EncryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut read = 0;
        while read < buf.len() {
            if self.buf.is_empty() {
                self.fill_buf()?;
                let seq = self.buf.as_slice().read_u64::<NetworkEndian>()?;
                if seq != self.seq {
                    return Err(Error::new(ErrorKind::InvalidData,
                                          "Secure channel integrity error"));
                }
                self.seq += 1;
                self.cursor += std::mem::size_of::<u64>();
            };
            let to_read = usize::min(self.buf.len()-self.cursor, buf.len()-read);
            (&mut buf[read..(read+to_read)])
                .clone_from_slice(
                    &self.buf[self.cursor..(self.cursor+to_read)]);
            self.cursor += to_read;
            read += to_read;
            if self.cursor == self.buf.len() {
                self.buf.clear();
                self.cursor = 0;
            }
        }
        Ok(buf.len())
    }
}

pub fn decrypt<'a>(key: &OpeningKey, nonce: &[u8; 12],
                   ciphertext_and_tag_modified_in_place: &'a mut [u8]) -> 
Result<&'a mut [u8]> {
    let nonce = Nonce::assume_unique_for_key(*nonce);
    open_in_place(key, nonce, Aad::empty(), 0, 
                  ciphertext_and_tag_modified_in_place)
        .map_err(|_| Error::new(ErrorKind::InvalidData,
                                    "Secure channel integrity error"))
}
