use ring::{agreement, error};
use crate::random::RandomState;
use crate::cmac::{MAC_LEN, Cmac};

const DHKE_PUBKEY_LEN: usize = 65; 
const KDK_LEN: usize = MAC_LEN; 
pub type DHKEPublicKey = [u8; DHKE_PUBKEY_LEN];
pub type KDK = [u8; KDK_LEN];
pub type KeError = error::Unspecified;

static KE_ALG: &agreement::Algorithm = &agreement::ECDH_P256;

pub struct DHKE {
    private_key: agreement::EphemeralPrivateKey,
    public_key: DHKEPublicKey, 
}

impl DHKE {
    pub fn generate_keypair(rng: &RandomState) -> Result<Self, KeError> {
        let private_key = 
            agreement::EphemeralPrivateKey::generate(KE_ALG, rng.inner())?;
        let mut public_key: DHKEPublicKey = [0; DHKE_PUBKEY_LEN] ;
        (&mut public_key[..]).copy_from_slice(private_key
                                              .compute_public_key()?
                                              .as_ref());
        Ok(Self { private_key, public_key })
    }

    pub fn derive_key(self, peer_public_key: &DHKEPublicKey) -> Result<KDK, KeError> {
        agreement::agree_ephemeral(
            self.private_key,
            KE_ALG,
            untrusted::Input::from(peer_public_key),
            error::Unspecified,
            |ikm| {
                let cmac = Cmac::new(&[0; MAC_LEN]);
                let kdk = cmac.sign(ikm);
                Ok(kdk)
            })
    }

    pub fn get_public_key(&self) -> &DHKEPublicKey {
        &self.public_key
    }
}
