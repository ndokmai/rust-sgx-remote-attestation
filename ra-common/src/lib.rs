pub mod msg;
pub mod tcp;

use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::error::CryptoError;
/// Derive SMK, SK, MK, and VK according to
/// https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example
pub fn derive_secret_keys(kdk: &mut Cmac) -> Result<(MacTag, MacTag, MacTag, MacTag), CryptoError> {
    let smk_data = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let smk = kdk.sign(&smk_data)?;

    let sk_data = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let sk = kdk.sign(&sk_data)?;

    let mk_data = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let mk = kdk.sign(&mk_data)?;

    let vk_data = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let vk = kdk.sign(&vk_data)?;

    Ok((smk, sk, mk, vk))
}
