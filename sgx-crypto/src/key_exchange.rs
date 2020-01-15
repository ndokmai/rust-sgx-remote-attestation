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

    /// Bob signs the (g_b, g_a).
    pub fn sign_and_derive(self, 
                           g_a: &DHKEPublicKey,
                           signing_key: &SigningKey, 
                           rng: &RandomState) 
        -> Result<(KDK, Signature), KeError> {

            // Sign (g_b, g_a) with Bob's signing key 
            let mut gb_ga = Vec::new();
            gb_ga.write_all(&self.dhke.public_key).unwrap();
            gb_ga.write_all(g_a).unwrap();
            let sign_gb_ga = signing_key.sign(&gb_ga[..], rng)
                .map_err(|e| KeError::SigError(e))?;

            // Derive KDK
            let kdk = self.dhke.derive_key(g_a)?;
            Ok((kdk, sign_gb_ga))
        } 

    /// Alice verifies the (g_b, g_a).
    pub fn verify_and_derive(self,
                             g_b: &DHKEPublicKey,
                             sign_gb_ga: &Signature,
                             verification_key: &VerificationKey) 
        -> Result<KDK, KeError> {

            // Verify (g_b, g_a) with Bob's verification key 
            let mut gb_ga = Vec::new();
            gb_ga.write_all(g_b).unwrap();
            gb_ga.write_all(&self.dhke.public_key).unwrap();
            verification_key.verify(&gb_ga[..], &sign_gb_ga[..])
                .map_err(|e| KeError::SigError(e))?;

            // Derive KDK
            self.dhke.derive_key(g_b)

        }
}
