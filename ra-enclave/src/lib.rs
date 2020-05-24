mod context;
mod error;
pub mod local_attestation;

pub use crate::context::*;
pub use crate::error::*;

pub type EnclaveRaResult<T> = Result<T, EnclaveRaError>;
