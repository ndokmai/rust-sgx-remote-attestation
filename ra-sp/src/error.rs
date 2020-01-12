
#[derive(Debug)]
pub enum SpRaError {
    IO(std::io::Error),
    KeyExchange(sgx_crypto::key_exchange::KeError),
    Signature(sgx_crypto::signature::SigError),
    Certificate(sgx_crypto::certificate::CertError),
    IAS(IasError),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    IntegrityError,
    SigstructMismatched,
    EnclaveInDebugMode,
    EnclaveNotTrusted,

}

impl std::convert::From<std::io::Error> for SpRaError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<sgx_crypto::key_exchange::KeError> for SpRaError {
    fn from(e: sgx_crypto::key_exchange::KeError) -> Self { Self::KeyExchange(e) }
}

impl std::convert::From<sgx_crypto::signature::SigError> for SpRaError {
    fn from(e: sgx_crypto::signature::SigError) -> Self { Self::Signature(e) }
}

impl std::convert::From<sgx_crypto::certificate::CertError> for SpRaError {
    fn from(e: sgx_crypto::certificate::CertError) -> Self { Self::Certificate(e) }
}

impl std::convert::From<IasError> for SpRaError {
    fn from(e: IasError) -> Self { Self::IAS(e) }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for SpRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self { Self::Serialization(e) }
}

impl std::fmt::Display for SpRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) 
        -> Result<(), std::fmt::Error> { 
            write!(f, "{:?}", self)
        }
}

impl std::error::Error for SpRaError {}


#[derive(Debug)]
pub enum AttestationError {
    Connection(http::StatusCode),
    MismatchedIASRootCertificate,
    InvalidIASCertificate,
    BadSignature,
}

#[derive(Debug)]
pub enum IasError {
    IO(std::io::Error),
    Connection(hyper::error::Error),
    SigRLError(http::StatusCode),
    Attestation(AttestationError),
}

impl std::convert::From<std::io::Error> for IasError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<hyper::error::Error> for IasError {
    fn from(e: hyper::error::Error) -> Self { Self::Connection(e) }
}
