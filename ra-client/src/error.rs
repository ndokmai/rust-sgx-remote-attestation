#[derive(Debug)]
pub enum ClientRaError {
    IO(std::io::Error),
    Aesm(aesm_client::Error),
    Serialization(std::boxed::Box<bincode::ErrorKind>),
    EnclaveNotTrusted,
}

impl std::convert::From<std::io::Error> for ClientRaError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<aesm_client::Error> for ClientRaError {
    fn from(e: aesm_client::Error) -> Self { Self::Aesm(e) }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for ClientRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self { Self::Serialization(e) }
}
