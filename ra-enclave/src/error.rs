#[derive(Debug)]
pub enum EnclaveRaError {
    KeyExchange(sgx_crypto::key_exchange::KeError),
    Signature(sgx_crypto::signature::SigError),
    IntegrityError,
    LocalAttestation(LocalAttestationError),
    EnclaveNotTrusted,
    PseNotTrusted,
}

impl std::convert::From<sgx_crypto::key_exchange::KeError> for EnclaveRaError {
    fn from(e: sgx_crypto::key_exchange::KeError) -> Self { Self::KeyExchange(e) }
}

impl std::convert::From<sgx_crypto::signature::SigError> for EnclaveRaError {
    fn from(e: sgx_crypto::signature::SigError) -> Self { Self::Signature(e) }
}

#[derive(Debug)]
pub enum LocalAttestationError {
    IncorrectReportLength,
    IntegrityError,
}

