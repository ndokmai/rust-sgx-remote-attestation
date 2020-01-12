pub mod local_attestation;
mod error;
mod context;

pub use crate::error::*;
pub use crate::context::*;

pub type EnclaveRaResult<T> = Result<T, EnclaveRaError>;
