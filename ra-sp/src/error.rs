#[derive(Debug)]
pub enum SpRaError {
    Crypto(sgx_crypto::error::CryptoError),
    IO(std::io::Error),
    IAS(IasError),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    IntegrityError,
    SigstructMismatched,
    EnclaveInDebugMode,
    EnclaveNotTrusted,
}

impl std::convert::From<std::io::Error> for SpRaError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::convert::From<sgx_crypto::error::CryptoError> for SpRaError {
    fn from(e: sgx_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::convert::From<IasError> for SpRaError {
    fn from(e: IasError) -> Self {
        Self::IAS(e)
    }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for SpRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self {
        Self::Serialization(e)
    }
}

impl std::fmt::Display for SpRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
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
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::convert::From<hyper::error::Error> for IasError {
    fn from(e: hyper::error::Error) -> Self {
        Self::Connection(e)
    }
}
