pub mod error;
pub mod random;
pub mod cmac;
pub mod digest;
pub mod key_exchange;
pub mod signature;
pub mod certificate;
pub mod tls_psk; 

pub type Result<T> = std::result::Result<T, error::CryptoError>;
