mod error;
mod context;

pub use crate::error::*;
pub use crate::context::*;

pub type ClientRaResult<T> = Result<T, ClientRaError>;
