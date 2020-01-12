use std::mem::size_of;
use ring::agreement;
use crate::random::RandomState;
use crate::cmac::{MacTag, Cmac};

const DHKE_PUBKEY_LEN: usize = 65; 
const KDK_LEN: usize = size_of::<MacTag>(); 
static KE_ALG: &agreement::Algorithm = &agreement::ECDH_P256;

pub type DHKEPublicKey = [u8; DHKE_PUBKEY_LEN];
pub type KDK = [u8; KDK_LEN];

#[derive(Debug)]
pub enum KeError {
    KeyGenerationError,
    KeyDerivationError
}

pub struct DHKE {
    private_key: agreement::EphemeralPrivateKey,
    public_key: DHKEPublicKey, 
}

impl DHKE {
    pub fn generate_keypair(rng: &RandomState) -> Result<Self, KeError> {
        let private_key = 
            agreement::EphemeralPrivateKey::generate(KE_ALG, rng.inner())
            .map_err(|_| KeError::KeyGenerationError)?;
        let mut public_key: DHKEPublicKey = [0; DHKE_PUBKEY_LEN] ;
        (&mut public_key[..]).copy_from_slice(private_key
                                              .compute_public_key()
                                              .map_err(|_| KeError::KeyGenerationError)?
                                              .as_ref());
        Ok(Self { private_key, public_key })
    }

    pub fn derive_key(self, peer_public_key: &DHKEPublicKey) -> Result<KDK, KeError> {
        agreement::agree_ephemeral(
            self.private_key,
            KE_ALG,
            untrusted::Input::from(peer_public_key),
            (),
            |ikm| {
                let cmac = Cmac::new(&[0; size_of::<MacTag>()]);
                let kdk = cmac.sign(ikm);
                Ok(kdk)
            }).map_err(|_| KeError::KeyDerivationError)
    }

    pub fn get_public_key(&self) -> &DHKEPublicKey {
        &self.public_key
    }
}
