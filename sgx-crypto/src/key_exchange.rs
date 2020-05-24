use super::cmac::{Cmac, MAC_LEN};
use super::random::Rng;
use super::signature::{Signature, SigningKey, VerificationKey};
use mbedtls::ecp::EcPoint;
use mbedtls::pk::{EcGroupId, Pk};
use std::io::Write;

const ECGROUP_ID: EcGroupId = EcGroupId::SecP256R1;
const SECRET_SHARE_LEN: usize = 32;
pub type DHKEPublicKey = Vec<u8>;
pub type KDK = [u8; MAC_LEN];

pub struct DHKE {
    inner: Pk,
}

impl DHKE {
    pub fn generate_keypair(rng: &mut Rng) -> super::Result<Self> {
        Ok(Self {
            inner: Pk::generate_ec(&mut rng.inner, ECGROUP_ID)?,
        })
    }

    pub fn get_public_key(&self) -> super::Result<DHKEPublicKey> {
        let ecgroup = self.inner.ec_group()?;
        Ok(self.inner.ec_public()?.to_binary(&ecgroup, true)?)
    }

    /// RNG is used to implement countermeasures against side-channel attacks. See https://tls.mbed.org/api/ecdh_8h.html#a423fee27a0c8603bba336cbfe6dadcaa
    pub fn derive_key(
        mut self,
        peer_public_key: &DHKEPublicKey,
        rng: &mut Rng,
    ) -> super::Result<KDK> {
        let mut ikm = vec![0; SECRET_SHARE_LEN];
        let ecgroup = self.inner.ec_group()?;
        let peer_public_key = Pk::public_from_ec_components(
            ecgroup.clone(),
            EcPoint::from_binary(&ecgroup, &peer_public_key[..])?,
        )?;
        let len = self
            .inner
            .agree(&peer_public_key, &mut ikm[..], &mut rng.inner)?;
        assert_eq!(len, SECRET_SHARE_LEN);
        let cmac_key = [0u8; MAC_LEN];
        let mut kdf = Cmac::new(&cmac_key[..])?;
        let out = kdf.sign(&ikm[..])?;
        Ok(out)
    }
}

/// One-way authenticated DHKE. Alice (g_a) verifies and Bob (g_b) signs.
pub struct OneWayAuthenticatedDHKE {
    inner: DHKE,
}

impl OneWayAuthenticatedDHKE {
    pub fn generate_keypair(rng: &mut Rng) -> super::Result<Self> {
        let inner = DHKE::generate_keypair(rng)?;
        Ok(Self { inner })
    }

    pub fn get_public_key(&self) -> super::Result<DHKEPublicKey> {
        self.inner.get_public_key()
    }

    /// Bob signs the (g_b, g_a).
    pub fn sign_and_derive(
        self,
        g_a: &DHKEPublicKey,
        signing_key: &mut SigningKey,
        rng: &mut Rng,
    ) -> super::Result<(KDK, Signature)> {
        // Sign (g_b, g_a) with Bob's signing key
        let mut gb_ga = Vec::new();
        gb_ga.write_all(&self.inner.get_public_key()?).unwrap();
        gb_ga.write_all(g_a).unwrap();
        let sign_gb_ga = signing_key.sign(&gb_ga[..], rng)?;

        // Derive KDK
        let kdk = self.inner.derive_key(g_a, rng)?;
        Ok((kdk, sign_gb_ga))
    }

    /// Alice verifies the (g_b, g_a).
    pub fn verify_and_derive(
        self,
        g_b: &DHKEPublicKey,
        sign_gb_ga: &Signature,
        verification_key: &mut VerificationKey,
        rng: &mut Rng,
    ) -> super::Result<KDK> {
        // Verify (g_b, g_a) with Bob's verification key
        let mut gb_ga = Vec::new();
        gb_ga.write_all(g_b).unwrap();
        gb_ga.write_all(&self.inner.get_public_key()?).unwrap();
        verification_key.verify(&gb_ga[..], &sign_gb_ga[..])?;

        // Derive KDK
        self.inner.derive_key(g_b, rng)
    }
}
