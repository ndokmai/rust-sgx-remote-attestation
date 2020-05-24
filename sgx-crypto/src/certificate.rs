use super::digest::{sha256, SHA256_TYPE};
use mbedtls::x509::Certificate;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct X509Cert {
    inner: Certificate,
}

impl X509Cert {
    pub fn new_from_der(x509_der: &[u8]) -> super::Result<Self> {
        let inner = Certificate::from_der(x509_der)?;
        Ok(Self { inner })
    }

    /// Input must be NULL-terminated
    pub fn new_from_pem(x509_pem: &[u8]) -> super::Result<Self> {
        let inner = Certificate::from_pem(x509_pem)?;
        Ok(Self { inner })
    }

    pub fn new_from_der_file(x509_der_path: &Path) -> super::Result<Self> {
        let mut file = File::open(x509_der_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Self::new_from_pem(&buf[..])
    }

    pub fn new_from_pem_file(x509_pem_path: &Path) -> super::Result<Self> {
        let mut file = File::open(x509_pem_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        buf.push(0);
        Self::new_from_pem(&buf[..])
    }

    pub fn verify_this_certificate(&mut self, trust_ca: &mut Self) -> super::Result<()> {
        self.inner.verify(&mut trust_ca.inner, None)?;
        Ok(())
    }

    pub fn verify_signature(&mut self, message: &[u8], signature: &[u8]) -> super::Result<()> {
        let hash = sha256(message)?;
        self.inner
            .public_key_mut()
            .verify(SHA256_TYPE, &hash[..], signature)?;
        Ok(())
    }
}

impl PartialEq for X509Cert {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_der() == other.inner.as_der()
    }
}
