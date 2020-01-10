pub mod error;
pub mod ias;

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::mem::size_of;
use serde::Deserialize;
use byteorder::{ReadBytesExt, LittleEndian};
use sgxs::sigstruct;
use crypto::random::RandomState;
use crypto::key_exchange::{DHKE, DHKEPublicKey};
use crypto::cmac::{Cmac, MacTag};
use crypto::signature::{SigningKey, X509Cert};
use crypto::sha256::{sha256, Sha256Digest};
use ra_common::msg::{Spid, RaMsg1, RaMsg2, RaMsg3, RaMsg4};
use ra_common::{derive_secret_keys, Stream};
use crate::error::SpRaError;
use crate::ias::IasClient;

#[derive(Deserialize, Debug)]
pub struct SpConfig {
    pub quote_type: u16,
    pub spid: String,
    pub primary_subscription_key: String,
    pub secondary_subscription_key: String,
    pub quote_trust: Vec<String>,
    pub pse_trust: Option<Vec<String>>,
    pub sp_private_key_pem_path: String,
    pub ias_root_cert_pem_path: String,
    pub sigstruct_path: String,
}

pub type SpRaResult<T> = Result<T, SpRaError>;

pub struct SpRaContext {
    quote_type: u16,
    spid: Spid, 
    primary_subscription_key: String,
    _secondary_subscription_key: String,
    quote_trust: Vec<String>,
    pse_trust: Option<Vec<String>>,
    sp_private_key: SigningKey, 
    sigstruct: sigstruct::Sigstruct,
    ias_client: IasClient, 
    rng: RandomState,
    b: Option<DHKE>,
    g_a: Option<DHKEPublicKey>, 
    g_b: DHKEPublicKey, 
    smk: Option<Cmac>,
    vk: Option<MacTag>,
    sk: Option<MacTag>,
    mk: Option<MacTag>,
}

impl SpRaContext {
    pub async fn do_attestation(mut self, 
                                mut client_stream: &mut impl Stream) 
        -> SpRaResult<(MacTag, MacTag)> {
            let msg1: RaMsg1 = bincode::deserialize_from(&mut client_stream)?;
            let msg2 = self.process_msg_1(msg1).await?;
            bincode::serialize_into(&mut client_stream, &msg2)?;
            let msg3: RaMsg3 = bincode::deserialize_from(&mut client_stream)?;
            let msg4 = self.process_msg_3(msg3).await?;
            bincode::serialize_into(&mut client_stream, &msg4)?;
            if !msg4.is_enclave_trusted {
                return Err(SpRaError::EnclaveNotTrusted);
            }
            match msg4.is_pse_manifest_trusted {
                Some(t) => if !t {
                        return Err(SpRaError::EnclaveNotTrusted);
                    },
                None => {},
            }
            Ok((self.sk.take().unwrap(), self.mk.take().unwrap()))
        }

    pub fn init(config: &SpConfig) -> SpRaResult<Self> {
        let mut spid = [0u8; size_of::<Spid>()];
        spid.copy_from_slice(&hex::decode(&config.spid)
                             .expect("Invalid SPID format")[..]);
        let mut quote_trust = config.quote_trust.clone();
        quote_trust.sort();
        let pse_trust = config.pse_trust.clone();
        let pse_trust = pse_trust.map(|mut i| {i.sort(); i});
        let cert = X509Cert::new_from_pem_file(
            Path::new(&config.ias_root_cert_pem_path))?;
        let rng = RandomState::new();
        let b = DHKE::generate_keypair(&rng)?;
        let g_b = *b.get_public_key();
        let mut sigstruct = File::open(Path::new(&config.sigstruct_path))?;
        let sigstruct = sigstruct::read(&mut sigstruct)?;

        Ok(Self {
            quote_type: config.quote_type,
            spid,
            primary_subscription_key: config.primary_subscription_key.to_owned(),
            _secondary_subscription_key: config.secondary_subscription_key.to_owned(),
            quote_trust,
            pse_trust,
            sp_private_key: SigningKey::new_from_pem_file(
                Path::new(&config.sp_private_key_pem_path))?,
            sigstruct,
            ias_client: IasClient::new(cert),
            rng,
            b: Some(b),
            g_a: None,
            g_b,
            smk: None,
            vk: None,
            sk: None,
            mk: None,
        })
    }

    pub async fn process_msg_1(&mut self, msg1: RaMsg1) -> SpRaResult<RaMsg2> {
        // get sigRL
        let sig_rl = self.ias_client
            .get_sig_rl(&msg1.gid, &self.primary_subscription_key);

        // derive KDK and other secret keys 
        let kdk_cmac = Cmac::new(&self.b.take().unwrap().derive_key(&msg1.g_a)?);
        let (smk, sk, mk, vk) = derive_secret_keys(&kdk_cmac);
        let smk = Cmac::new(&smk);

        // Sign (g_b, g_a) with SP's signing key 
        let mut gb_ga = Vec::new();
        gb_ga.write_all(&self.g_b)?;
        gb_ga.write_all(&msg1.g_a)?;
        let sign_gb_ga = self.sp_private_key.sign(&gb_ga[..], &self.rng)?;

        // Set context
        self.g_a = Some(msg1.g_a);
        self.smk = Some(smk);
        self.vk = Some(vk);
        self.sk = Some(sk);
        self.mk = Some(mk);

        Ok(RaMsg2::new(
            self.smk.as_ref().unwrap(),
            self.g_b,
            self.spid,
            self.quote_type,
            sign_gb_ga,
            sig_rl.await?,
        ))
    }

    pub async fn process_msg_3(&mut self, msg3: RaMsg3) -> SpRaResult<RaMsg4> {
        // Integrity check
        if &msg3.g_a.as_ref()[..] != &self.g_a.as_ref().unwrap()[..] {
            return Err(SpRaError::Integrity);
        }
        if !msg3.verify_mac(self.smk.as_ref().unwrap()) {
            return Err(SpRaError::Integrity);
        }
        let mut verification_msg = Vec::new();
        verification_msg.write_all(&msg3.g_a)?;
        verification_msg.write_all(self.g_b.as_ref())?;
        verification_msg.write_all(self.vk.as_ref().unwrap())?;
        let verification_digest = sha256(&verification_msg[..]);
        let loc = 368;
        let mut quote_digest = [0u8; size_of::<Sha256Digest>()];
        quote_digest.copy_from_slice(&msg3.quote.as_ref()[loc..(loc+32)]);
        if verification_digest != quote_digest {
            return Err(SpRaError::Integrity);
        }

        // Verify attestation evidence
        let attestation_result = self.ias_client
            .verify_attestation(&msg3.quote, &self.primary_subscription_key).await?;

        // Verify enclave identity
        let mrenclave = &msg3.quote[112..144];
        let mrsigner = &msg3.quote[176..208];
        let isvprodid = (&msg3.quote[304..306]).read_u16::<LittleEndian>()?;
        let isvsvn = (&msg3.quote[306..308]).read_u16::<LittleEndian>()?;
        if mrenclave != &self.sigstruct.enclavehash[..] ||
            mrsigner != &sha256(&self.sigstruct.modulus[..])[..] ||
                isvprodid != self.sigstruct.isvprodid ||
                isvsvn != self.sigstruct.isvsvn {
                    return Err(SpRaError::Integrity)
                }

        let attribute_flags = &self.sigstruct.attributes.flags;
        // this should be true when debug
        assert!((&sgx_isa::AttributesFlags::DEBUG).intersects(*attribute_flags));
        // this should be true when in production mode
        //assert!(!(&sgx_isa::AttributesFlags::DEBUG).intersects(*attribute_flags));

        // Decide whether to trust enclave
        let quote_status = attestation_result.isv_enclave_quote_status.clone();
        let pse_manifest_status = attestation_result.pse_manifest_status.clone();
        let is_enclave_trusted = (quote_status == "OK") || 
            match self.quote_trust.binary_search(&quote_status) {
                Ok(_) => true,
                Err(_) => false,
            };
        let is_pse_manifest_trusted = pse_manifest_status.map(
            |status| (status == "OK") ||
            match self.pse_trust.as_ref().unwrap().binary_search(&status) {
                Ok(_) => true,
                Err(_) => false,
            }); 

        Ok(RaMsg4 {
            is_enclave_trusted,
            is_pse_manifest_trusted,
            pib: attestation_result.platform_info_blob,
        })
    }
}
