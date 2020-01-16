use std::io::Write;
use std::mem::size_of;
use ring::agreement;
use crate::random::RandomState;
use crate::cmac::{MacTag, Cmac};
use crate::signature::{SigningKey, VerificationKey, Signature, SigError};

const DHKE_PUBKEY_LEN: usize = 65; 
const KDK_LEN: usize = size_of::<MacTag>(); 
static KE_ALG: &agreement::Algorithm = &agreement::ECDH_P256;

pub type DHKEPublicKey = [u8; DHKE_PUBKEY_LEN];
pub type KDK = [u8; KDK_LEN];

#[derive(Debug)]
pub enum KeError {
    KeyGenerationError,
    KeyDerivationError,
    SigError(SigError),
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

    pub fn get_public_key(&self) -> &DHKEPublicKey {
        &self.public_key
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

}

/// One-way authenticated DHKE. Alice (g_a) verifies and Bob (g_b) signs.
pub struct OneWayAuthenticatedDHKE {
    dhke: DHKE,
}

impl OneWayAuthenticatedDHKE {
    pub fn generate_keypair(rng: &RandomState) -> Result<Self, KeError> {
        let dhke = DHKE::generate_keypair(rng)?;
        Ok(Self { dhke })
    }

    pub fn get_public_key(&self) -> &DHKEPublicKey {
        &self.dhke.public_key
    }

    /// Bob signs (g_b || g_a || aad).
    pub fn sign_and_derive(self, 
                           g_a: &DHKEPublicKey,
                           signing_key: &SigningKey, 
                           aad: Option<&[u8]>, // additionally authenticated data
                           rng: &RandomState) 
        -> Result<(KDK, Signature), KeError> {

            // Sign (g_b || g_a || aad) with Bob's signing key 
            let mut msg = Vec::new();
            msg.write_all(&self.dhke.public_key).unwrap();
            msg.write_all(g_a).unwrap();
            if aad.is_some() {
                msg.write_all(aad.as_ref().unwrap()).unwrap();
            }
            let signature = signing_key.sign(&msg[..], rng)
                .map_err(|e| KeError::SigError(e))?;

            // Derive KDK
            let kdk = self.dhke.derive_key(g_a)?;
            Ok((kdk, signature))
        } 

    /// Alice verifies (g_b || g_a || aad).
    pub fn verify_and_derive(self,
                             g_b: &DHKEPublicKey,
                             signature: &Signature, // Sig(g_b || g_a || aad)
                             aad: Option<&[u8]>, // additionally authenticated data
                             verification_key: &VerificationKey) 
        -> Result<KDK, KeError> {

            // Verify (g_b || g_a || aad) with Bob's verification key 
            let mut msg = Vec::new();
            msg.write_all(g_b).unwrap();
            msg.write_all(&self.dhke.public_key).unwrap();
            if aad.is_some() {
                msg.write_all(aad.as_ref().unwrap()).unwrap();
            }
            verification_key.verify(&msg[..], &signature[..])
                .map_err(|e| KeError::SigError(e))?;

            // Derive KDK
            self.dhke.derive_key(g_b)

        }
}
