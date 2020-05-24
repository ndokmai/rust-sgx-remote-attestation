use std::io;

#[derive(Debug)]
pub enum CryptoError {
    MbedTls(mbedtls::Error),
    Io(io::Error),
    CmacVerificationError,
}

impl std::convert::From<mbedtls::Error> for CryptoError {
    fn from(e: mbedtls::Error) -> Self {
        Self::MbedTls(e)
    }
}

impl std::convert::From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
