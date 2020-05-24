mod context;
mod error;

pub use crate::context::*;
pub use crate::error::*;

pub type ClientRaResult<T> = Result<T, ClientRaError>;
