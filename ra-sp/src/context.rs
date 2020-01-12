use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::convert::TryInto;
use byteorder::{ReadBytesExt, LittleEndian};
use sgxs::sigstruct;
use sgx_crypto::random::RandomState;
use sgx_crypto::key_exchange::{DHKE, DHKEPublicKey};
use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::signature::SigningKey;
use sgx_crypto::certificate::X509Cert;
use sgx_crypto::digest::{sha256, Sha256Digest};
use ra_common::msg::{Spid, RaMsg0, RaMsg1, RaMsg2, RaMsg3, RaMsg4};
use ra_common::{derive_secret_keys, Stream};
use crate::ias::{IasClient};
use crate::config::SpConfig;
use crate::error::SpRaError;
use crate::{SpRaResult, AttestationResult};

pub struct SpRaContext {
    config: SpConfig,
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
    pub fn init(mut config: SpConfig) -> SpRaResult<Self> {
        assert!(config.linkable, "Only Linkable Quote supported");
        assert!(!config.random_nonce, "Random nonces not supported");
        assert!(!config.use_platform_service, "Platform service not supported");
        if cfg!(feature = "verbose") {
            eprintln!("==================SP Config==================");
            eprintln!("{:#?}", config);
            eprintln!("=============================================");
        }

        // Preparing for binary search
        config.quote_trust_options.sort();
        config.pse_trust_options.as_mut().map(|v| v.sort());

        let sp_private_key = SigningKey::new_from_pem_file(
            Path::new(&config.sp_private_key_pem_path))?;

        let cert = X509Cert::new_from_pem_file(
            Path::new(&config.ias_root_cert_pem_path))?;

        let rng = RandomState::new();

        let b = DHKE::generate_keypair(&rng)?;
        let g_b = *b.get_public_key();

        let mut sigstruct = File::open(Path::new(&config.sigstruct_path))?;
        let sigstruct = sigstruct::read(&mut sigstruct)?;

        Ok(Self {
            config,
            sp_private_key,
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

    #[tokio::main]
    pub async fn do_attestation(mut self, 
                                mut client_stream: &mut impl Stream) 
        -> SpRaResult<AttestationResult> {
            // Not using MSG0 for now.
            let _msg0: RaMsg0 = bincode::deserialize_from(&mut client_stream)?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG0 received ");
            }

            let msg1: RaMsg1 = bincode::deserialize_from(&mut client_stream)?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG1 received");
            }

            let msg2 = self.process_msg_1(msg1).await?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG1 processed");
            }

            bincode::serialize_into(&mut client_stream, &msg2)?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG2 sent");
            }

            let msg3: RaMsg3 = bincode::deserialize_from(&mut client_stream)?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG3 received");
            }

            let (msg4, epid_pseudonym) = self.process_msg_3(msg3).await?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG4 generated");
            }

            bincode::serialize_into(&mut client_stream, &msg4)?;
            if cfg!(feature = "verbose") {
                eprintln!("MSG4 sent");
            }

            if !msg4.is_enclave_trusted {
                return Err(SpRaError::EnclaveNotTrusted);
            }
            match msg4.is_pse_manifest_trusted {
                Some(t) => if !t {
                        return Err(SpRaError::EnclaveNotTrusted);
                    },
                None => {},
            }

            Ok(AttestationResult {
                epid_pseudonym,
                secret_key: self.sk.take().unwrap(),
                mac_key: self.mk.take().unwrap()
            })
        }

    pub async fn process_msg_1(&mut self, msg1: RaMsg1) -> SpRaResult<RaMsg2> {
        // get sigRL
        let sig_rl = self.ias_client
            .get_sig_rl(&msg1.gid, &self.config.primary_subscription_key);

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

        let spid: Spid = hex::decode(&self.config.spid).unwrap().as_slice()
            .try_into().unwrap();
        let quote_type = self.config.linkable as u16;

        Ok(RaMsg2::new(
            self.smk.as_ref().unwrap(),
            self.g_b,
            spid,
            quote_type, 
            sign_gb_ga,
            sig_rl.await?,
        ))
    }

    pub async fn process_msg_3(&mut self, msg3: RaMsg3) 
        -> SpRaResult<(RaMsg4, Option<String>)> {
            // Integrity check
            if &msg3.g_a.as_ref()[..] != &self.g_a.as_ref().unwrap()[..] {
                return Err(SpRaError::IntegrityError);
            }
            if !msg3.verify_mac(self.smk.as_ref().unwrap()).is_ok() {
                return Err(SpRaError::IntegrityError);
            }
            let mut verification_msg = Vec::new();
            verification_msg.write_all(&msg3.g_a).unwrap();
            verification_msg.write_all(self.g_b.as_ref()).unwrap();
            verification_msg.write_all(self.vk.as_ref().unwrap()).unwrap();
            let verification_digest = sha256(&verification_msg[..]);
            let quote_digest: Sha256Digest = (&msg3.quote.as_ref()[368..400])
                .try_into().unwrap();
            if verification_digest != quote_digest {
                return Err(SpRaError::IntegrityError);
            }

            // Verify attestation evidence
            // TODO: use the secondary key as well
            let attestation_result = self.ias_client
                .verify_attestation_evidence(
                    &msg3.quote, 
                    &self.config.primary_subscription_key).await?;

            if cfg!(feature = "verbose") {
                eprintln!("==============Attestation Result==============");
                eprintln!("{:#?}", attestation_result);
                eprintln!("==============================================");
            }

            // Verify enclave identity
            let mrenclave = &msg3.quote[112..144];
            let mrsigner = &msg3.quote[176..208];
            let isvprodid = (&msg3.quote[304..306]).read_u16::<LittleEndian>().unwrap();
            let isvsvn = (&msg3.quote[306..308]).read_u16::<LittleEndian>().unwrap();
            if mrenclave != &self.sigstruct.enclavehash[..] ||
                mrsigner != &sha256(&self.sigstruct.modulus[..])[..] ||
                    isvprodid != self.sigstruct.isvprodid ||
                    isvsvn != self.sigstruct.isvsvn {
                        return Err(SpRaError::SigstructMismatched);
                    }

            // Make sure the enclave is not in debug mode in production
            let attribute_flags = &self.sigstruct.attributes.flags;
            if cfg!(not(debug_assertions)) {
                if (&sgx_isa::AttributesFlags::DEBUG).intersects(*attribute_flags) {
                    return Err(SpRaError::EnclaveInDebugMode);
                }
            }

            // Decide whether to trust enclave
            let quote_status = attestation_result.isv_enclave_quote_status.clone();
            let pse_manifest_status = attestation_result.pse_manifest_status.clone();
            let is_enclave_trusted = (quote_status == "OK") || 
                self.config.quote_trust_options.binary_search(&quote_status).is_ok();
            let is_pse_manifest_trusted = pse_manifest_status.map(
                |status| (status == "OK") ||
                self.config.pse_trust_options.as_ref().unwrap().binary_search(&status)
                .is_ok()); 

            Ok((RaMsg4 {
                is_enclave_trusted,
                is_pse_manifest_trusted,
                pib: attestation_result.platform_info_blob,
            },
            attestation_result.epid_pseudonym))
        }
}
