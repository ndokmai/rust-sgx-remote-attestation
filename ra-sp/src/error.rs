#[derive(Debug)]
pub enum SpRaError {
    IO(std::io::Error),
    KeyExchange(crypto::key_exchange::KeError),
    Signature(crypto::signature::SigError),
    IAS(crate::ias::IasError),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    Integrity,
    EnclaveNotTrusted,
}

impl std::convert::From<std::io::Error> for SpRaError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<crypto::key_exchange::KeError> for SpRaError {
    fn from(e: crypto::key_exchange::KeError) -> Self { Self::KeyExchange(e) }
}

impl std::convert::From<crypto::signature::SigError> for SpRaError {
    fn from(e: crypto::signature::SigError) -> Self { Self::Signature(e) }
}

impl std::convert::From<crate::ias::IasError> for SpRaError {
    fn from(e: crate::ias::IasError) -> Self { Self::IAS(e) }
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
