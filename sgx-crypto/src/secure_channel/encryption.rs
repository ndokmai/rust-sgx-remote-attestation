use std::io::{Write, Result, Error, ErrorKind};
use std::rc::Rc;
use std::cell::RefCell;
use ring::aead::{SealingKey, Nonce, Aad, seal_in_place, AES_128_GCM};
use ring::rand::{SystemRandom, SecureRandom};
use byteorder::{WriteBytesExt, NetworkEndian};

pub struct EncryptedWriter {
    inner: Rc<RefCell<dyn Write>>,
    buf: Vec<u8>,
    key: SealingKey,
    rand: SystemRandom,
    seq: u64,
    tag_len: usize,
    capacity: usize,
    // If the inner writer panics in a call to write, we don't want to
    // write the buffered data a second time in BufWriter's destructor. This
    // flag tells the Drop impl if it should skip the flush.
    panicked: bool,
}

impl EncryptedWriter {
    pub fn with_capacity(capacity: usize, inner: Rc<RefCell<dyn Write>>, 
                         key_bytes: &[u8; 16]) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity + AES_128_GCM.tag_len()),
            key: SealingKey::new(&AES_128_GCM, &key_bytes[..]).unwrap(),
            rand: SystemRandom::new(),
            seq: 0,
            tag_len: AES_128_GCM.tag_len(),
            capacity,
            panicked: false,
        }
    }

    fn flush_buf(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.buf.resize(self.buf.len()+self.tag_len, 0);
        let mut nonce = [0u8; 12];
        let len = encrypt(&self.key, &self.rand, &mut nonce,
                &mut self.buf[..]).unwrap();

        self.panicked = true;
        let r = self.inner.borrow_mut().write_u32::<NetworkEndian>(len as u32);
        self.panicked = false;
        match r {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        let mut written = 0;
        while written < nonce.len() {
            self.panicked = true;
            let r = self.inner.borrow_mut().write(&nonce[written..]);
            self.panicked = false;

            match r {
                Ok(0) => {
                    return Err(Error::new(ErrorKind::WriteZero,
                                         "Failed to write the buffered data"));
                }
                Ok(n) => written += n,
                Err(e) => { return Err(e); }
            }
        }

        let mut written = 0;
        while written < len {
            self.panicked = true;
            let r = self.inner.borrow_mut().write(&self.buf[written..]);
            self.panicked = false;

            match r {
                Ok(0) => {
                    return Err(Error::new(ErrorKind::WriteZero,
                                         "Failed to write the buffered data"));
                }
                Ok(n) => written += n,
                Err(e) => { return Err(e); }
            }
        }
        self.buf.clear();
        Ok(())
    }
}

impl Write for EncryptedWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        let len = buf.len();
        while written < len {
            if self.buf.len() == 0 {
                self.buf.write_u64::<NetworkEndian>(self.seq)?;
                self.seq += 1;
            }
            let to_write = usize::min(self.capacity - self.buf.len(), 
                                      buf.len() - written);
            written += self.buf.write(&buf[written..(written+to_write)])?;
            if self.buf.len() == self.capacity {
                self.flush_buf()?;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_buf().and_then(|()| self.inner.borrow_mut().flush())
    }
}

impl Drop for EncryptedWriter {
    fn drop(&mut self) {
        if !self.panicked {
            let _r = self.flush_buf();
        }
    }
}

fn encrypt(key: &SealingKey, rand: &SystemRandom, nonce: &mut [u8; 12],
               in_out: &mut [u8]) -> Result<usize> {
    rand.fill(nonce).unwrap();
    let nonce = Nonce::assume_unique_for_key(*nonce);
    seal_in_place(key, nonce, Aad::empty(), in_out, 
                            key.algorithm().tag_len())
        .map_err(|_| Error::new(ErrorKind::InvalidData,
                                    "Secure channel encryption error"))
}

