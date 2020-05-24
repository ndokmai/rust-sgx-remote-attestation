#[derive(Debug)]
pub enum EnclaveRaError {
    Crypto(sgx_crypto::error::CryptoError),
    IntegrityError,
    ReportDataLongerThan64Bytes,
    LocalAttestation(LocalAttestationError),
    EnclaveNotTrusted,
    PseNotTrusted,
}

impl std::convert::From<sgx_crypto::error::CryptoError> for EnclaveRaError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[derive(Debug)]
pub enum LocalAttestationError {
    Crypto(sgx_crypto::error::CryptoError),
    IncorrectReportLength,
    IntegrityError,
}

impl std::convert::From<sgx_crypto::error::CryptoError> for LocalAttestationError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
