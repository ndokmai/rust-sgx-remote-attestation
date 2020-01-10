#[derive(Debug)]
pub enum EnclaveRaError {
    IO(std::io::Error),
    KeyExchange(crypto::key_exchange::KeError),
    Signature(crypto::signature::SigError),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    Integrity,
    EnclaveNotTrusted,
}

impl std::convert::From<std::io::Error> for EnclaveRaError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<crypto::key_exchange::KeError> for EnclaveRaError {
    fn from(e: crypto::key_exchange::KeError) -> Self { Self::KeyExchange(e) }
}

impl std::convert::From<crypto::signature::SigError> for EnclaveRaError {
    fn from(e: crypto::signature::SigError) -> Self { Self::Signature(e) }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for EnclaveRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self { Self::Serialization(e) }
}
