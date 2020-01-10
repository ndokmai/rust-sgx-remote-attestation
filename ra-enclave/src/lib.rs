pub mod local_attestation;
pub mod error;

use std::io::Write;
use std::mem::size_of;
use sgx_isa::{Targetinfo, Report};
use crypto::random::RandomState;
use crypto::key_exchange::{DHKE, DHKEPublicKey};
use crypto::signature::VerificationKey;
use crypto::cmac::{Cmac, MacTag};
use crypto::sha256::sha256;
use ra_common::{Stream, derive_secret_keys};
use ra_common::msg::{PsSecPropDesc, Quote, RaMsg2, RaMsg3, RaMsg4};
use crate::error::EnclaveRaError;

pub type EnclaveRaResult<T> = Result<T, EnclaveRaError>;

pub struct EnclaveRaContext {
    pub sp_cert: VerificationKey,
    pub a: Option<DHKE>,
    pub g_a: DHKEPublicKey, 
    pub kdk: Option<MacTag>,
    pub smk: Option<Cmac>,
    pub vk: Option<MacTag>,
    pub sk: Option<MacTag>,
    pub mk: Option<MacTag>,
}

impl EnclaveRaContext {
    pub fn do_attestation(mut self, mut client_stream: &mut impl Stream) 
        -> Result<(MacTag, MacTag), EnclaveRaError> {
            client_stream.write_all(self.g_a.as_ref())?;
            self.process_msg_2(client_stream)?;
            let msg4: RaMsg4 = bincode::deserialize_from(&mut client_stream)?;
            if !msg4.is_enclave_trusted {
                return Err(EnclaveRaError::EnclaveNotTrusted);
            }
            match msg4.is_pse_manifest_trusted {
                Some(t) => if !t {
                    return Err(EnclaveRaError::EnclaveNotTrusted);
                },
                None => {},
            }
            Ok((self.sk.take().unwrap(), self.mk.take().unwrap()))
        }

    pub fn init(sp_cert_pem: &str) -> EnclaveRaResult<Self>  {
        let rng = RandomState::new();
        let a = DHKE::generate_keypair(&rng)?;
        let g_a = *a.get_public_key();
        Ok(Self {
            sp_cert: VerificationKey::new_from_pem(sp_cert_pem)?,
            a: Some(a),
            g_a,
            kdk: None,
            smk: None,
            vk: None,
            sk: None,
            mk: None,
        })
    }

    pub fn process_msg_2(&mut self, 
                         mut client_stream: &mut impl Stream) -> EnclaveRaResult<()> {
        let msg2: RaMsg2 = bincode::deserialize_from(&mut client_stream)?;

        // Derive KDK and other secret keys 
        let kdk = self.a.take().unwrap().derive_key(&msg2.g_b)?;
        let kdk_cmac = Cmac::new(&kdk);
        let (smk, sk, mk, vk) = derive_secret_keys(&kdk_cmac);
        let smk = Cmac::new(&smk);

        // Verify (g_b, g_a) with SP's certificate
        let mut gb_ga = Vec::new();
        gb_ga.write_all(&msg2.g_b)?;
        gb_ga.write_all(&self.g_a)?;
        self.sp_cert.verify(&gb_ga[..], &msg2.sign_gb_ga[..])?;

        // Verify mac tag
        if !msg2.verify_mac(&smk) {
            return Err(EnclaveRaError::Integrity);
        }

        // Obtain SHA-256(g_a || g_b || vk) 
        let mut verification_msg = Vec::new();
        verification_msg.write_all(self.g_a.as_ref())?;
        verification_msg.write_all(&msg2.g_b)?;
        verification_msg.write_all(&vk)?;
        let verification_digest = sha256(&verification_msg[..]);

        // Build a report and send it to client
        let mut report_data = [0u8; 64];
        (&mut report_data[..32]).copy_from_slice(&verification_digest[..]);
        let mut target_info = [0u8; Targetinfo::UNPADDED_SIZE];
        client_stream.read_exact(&mut target_info)?;
        let target_info = Targetinfo::try_copy_from(&target_info).unwrap();
        let report = Report::for_target(&target_info, &report_data);
        client_stream.write_all(report.as_ref())?;

        // Obtain quote and QE report from client 
        let mut quote = [0u8; size_of::<Quote>()];
        client_stream.read_exact(&mut quote[..])?;
        let qe_report_len = 432usize;
        let mut qe_report = vec![0u8; qe_report_len];
        client_stream.read_exact(&mut qe_report[..])?;

        // Verify that the report is generated by QE
        if !local_attestation::verify_local_attest(&qe_report[..]) {
            return Err(EnclaveRaError::Integrity)
        }

        // Read Platform Service's security property
        let mut ps_sec_prop = [0u8; size_of::<PsSecPropDesc>()];
        client_stream.read_exact(&mut ps_sec_prop)?;

        // Send MAC for msg3 to client
        let msg3 = RaMsg3::new(&smk, 
                               self.g_a, ps_sec_prop, 
                               quote);
        client_stream.write_all(&msg3.mac)?;

        // Set context
        self.kdk = Some(kdk);
        self.smk = Some(smk);
        self.vk = Some(vk);
        self.sk = Some(sk);
        self.mk = Some(mk);
        Ok(())
    }
}