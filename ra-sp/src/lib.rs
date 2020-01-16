mod ias;
mod attestation_response;
mod error;
mod context;
mod config;

pub use crate::error::*;
pub use crate::context::*;
pub use crate::config::*;

pub type SpRaResult<T> = Result<T, crate::error::SpRaError>;

use sgx_crypto::key_exchange::KDK;

pub struct AttestationResult {
    pub epid_pseudonym: Option<String>,
    pub kdk: KDK,
}

