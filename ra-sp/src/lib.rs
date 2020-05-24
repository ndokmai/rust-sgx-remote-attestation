mod attestation_response;
mod config;
mod context;
mod error;
mod ias;

pub use crate::config::*;
pub use crate::context::*;
pub use crate::error::*;

pub type SpRaResult<T> = Result<T, crate::error::SpRaError>;

use sgx_crypto::cmac::MacTag;

pub struct AttestationResult {
    pub epid_pseudonym: Option<String>,
    pub signing_key: MacTag,
    pub master_key: MacTag,
}
