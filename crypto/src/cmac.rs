// 128-bit AES-CMAC
use crypto_mac::Mac as InnerMacTrait;
use cmac::Cmac as InnerCmac;
use aes::Aes128;

pub const MAC_LEN: usize = 16;
pub type MacTag = [u8; MAC_LEN];

pub struct Cmac {
    key: [u8; MAC_LEN], 
}

impl Cmac {
    pub fn new(key: &[u8; MAC_LEN]) -> Self {
        Self {
            key: *key,
        }
    }

    pub fn sign(&self, data: &[u8]) -> MacTag {
        let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..]).unwrap();
        inner.input(data);
        let mac = inner.result_reset();
        mac.code().into()
    }

    pub fn verify(&self, data: &[u8], tag: &MacTag) -> bool {
        let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..]).unwrap();
        inner.input(data);
        match inner.verify(&tag[..]) {
            Ok(_) => true,
            Err(_) => false,
        }
    } 
}
