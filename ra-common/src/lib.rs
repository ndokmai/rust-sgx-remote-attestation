pub mod msg;
pub mod tcp;

use std::io::{Read, Write};
use crypto::cmac::{Cmac, MacTag};

pub trait Stream: Read + Write {}

// Return (smk, sk, mk, vk)
pub fn derive_secret_keys(kdk: &Cmac) -> (MacTag, MacTag, MacTag, MacTag) {
    let smk_data = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let smk = kdk.sign(&smk_data);

    let sk_data = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let sk = kdk.sign(&sk_data);

    let mk_data = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let mk = kdk.sign(&mk_data);

    let vk_data = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let vk = kdk.sign(&vk_data);

    (smk, sk, mk, vk)
}
