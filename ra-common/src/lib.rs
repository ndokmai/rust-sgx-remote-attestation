pub mod msg;
pub mod tcp;

use std::io::{Read, Write};
pub trait Stream: Read + Write {}
