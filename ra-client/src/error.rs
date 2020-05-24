#[derive(Debug)]
pub enum ClientRaError {
    IO(std::boxed::Box<bincode::ErrorKind>),
    Aesm(aesm_client::Error),
    EnclaveNotTrusted,
    PseNotTrusted,
}

impl std::convert::From<aesm_client::Error> for ClientRaError {
    fn from(e: aesm_client::Error) -> Self {
        Self::Aesm(e)
    }
}

impl std::convert::From<std::boxed::Box<bincode::ErrorKind>> for ClientRaError {
    fn from(e: std::boxed::Box<bincode::ErrorKind>) -> Self {
        Self::IO(e)
    }
}
