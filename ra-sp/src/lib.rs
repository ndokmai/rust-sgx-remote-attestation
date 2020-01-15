mod ias;
mod attestation_response;
mod error;
mod context;
mod config;

pub use crate::error::*;
pub use crate::context::*;
pub use crate::config::*;

pub type SpRaResult<T> = Result<T, crate::error::SpRaError>;

use sgx_crypto::cmac::MacTag;

pub struct AttestationResult {
    pub epid_pseudonym: Option<String>,
    pub signing_key: MacTag,
    pub master_key: MacTag,
}

