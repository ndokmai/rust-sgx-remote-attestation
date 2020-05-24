use crate::config::SpConfig;
use crate::error::SpRaError;
use crate::ias::IasClient;
use crate::{AttestationResult, SpRaResult};
use byteorder::{LittleEndian, ReadBytesExt};
use ra_common::derive_secret_keys;
use ra_common::msg::{RaMsg0, RaMsg1, RaMsg2, RaMsg3, RaMsg4, Spid};
use sgx_crypto::certificate::X509Cert;
use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::digest::{sha256, Sha256Digest};
use sgx_crypto::key_exchange::{DHKEPublicKey, OneWayAuthenticatedDHKE};
use sgx_crypto::random::EntropyCallback;
use sgx_crypto::random::Rng;
use sgx_crypto::signature::SigningKey;
use sgxs::sigstruct;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub struct SpRaContext<'a> {
    config: SpConfig,
    sigstruct: sigstruct::Sigstruct,
    ias_client: IasClient,
    sp_private_key: SigningKey,
    rng: Rng<'a>,
    key_exchange: Option<OneWayAuthenticatedDHKE>,
    g_a: Option<DHKEPublicKey>,
    verification_digest: Option<Sha256Digest>,
    smk: Option<Cmac>,
    sk_mk: Option<(MacTag, MacTag)>,
}

impl<'a> SpRaContext<'a> {
    pub fn init(mut config: SpConfig, enthropy: &'a mut impl EntropyCallback) -> SpRaResult<Self> {
        assert!(config.linkable, "Only Linkable Quote supported");
        assert!(!config.random_nonce, "Random nonces not supported");
        assert!(
            !config.use_platform_service,
            "Platform service not supported"
        );
        if cfg!(feature = "verbose") {
            eprintln!("==================SP Config==================");
            eprintln!("{:#?}", config);
            eprintln!("=============================================");
        }

        // Preparing for binary search
        config.quote_trust_options.sort();
        config.pse_trust_options.as_mut().map(|v| v.sort());

        let sp_private_key =
            SigningKey::new_from_file(Path::new(&config.sp_private_key_pem_path), None)?;

        let cert = X509Cert::new_from_pem_file(Path::new(&config.ias_root_cert_pem_path))?;

        let mut rng = Rng::new(enthropy)?;
        let key_exchange = OneWayAuthenticatedDHKE::generate_keypair(&mut rng)?;

        let mut sigstruct = File::open(Path::new(&config.sigstruct_path))?;
        let sigstruct = sigstruct::read(&mut sigstruct)?;

        Ok(Self {
            config,
            sigstruct,
            ias_client: IasClient::new(cert),
            sp_private_key,
            rng,
            key_exchange: Some(key_exchange),
            g_a: None,
            verification_digest: None,
            smk: None,
            sk_mk: None,
        })
    }

    #[tokio::main]
    pub async fn do_attestation(
        mut self,
        mut client_stream: &mut (impl Read + Write),
    ) -> SpRaResult<AttestationResult> {
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
            Some(t) => {
                if !t {
                    return Err(SpRaError::EnclaveNotTrusted);
                }
            }
            None => {}
        }

        let (signing_key, master_key) = self.sk_mk.take().unwrap();

        Ok(AttestationResult {
            epid_pseudonym,
            signing_key,
            master_key,
        })
    }

    pub async fn process_msg_1(&mut self, msg1: RaMsg1) -> SpRaResult<RaMsg2> {
        // Get sigRL
        let sig_rl = self
            .ias_client
            .get_sig_rl(&msg1.gid, &self.config.primary_subscription_key);

        let key_exchange = self.key_exchange.take().unwrap();
        let g_b = key_exchange.get_public_key()?;

        // Sign and derive KDK and other secret keys
        let (kdk, sign_gb_ga) =
            key_exchange.sign_and_derive(&msg1.g_a, &mut self.sp_private_key, &mut self.rng)?;
        let mut kdk_cmac = Cmac::new(&kdk)?;
        let (smk, sk, mk, vk) = derive_secret_keys(&mut kdk_cmac)?;
        let smk = Cmac::new(&smk)?;

        // Obtain SHA-256(g_a || g_b || vk)
        let mut verification_msg = Vec::new();
        verification_msg.write_all(&msg1.g_a).unwrap();
        verification_msg.write_all(&g_b[..]).unwrap();
        verification_msg.write_all(&vk).unwrap();
        let verification_digest = sha256(&verification_msg[..])?;

        // Set context
        self.smk = Some(smk);
        self.sk_mk = Some((sk, mk));
        self.verification_digest = Some(verification_digest);
        self.g_a = Some(msg1.g_a.clone());

        let spid: Spid = hex::decode(&self.config.spid)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let quote_type = self.config.linkable as u16;

        Ok(RaMsg2::new(
            self.smk.as_mut().unwrap(),
            g_b,
            spid,
            quote_type,
            sign_gb_ga,
            sig_rl.await?,
        )?)
    }

    pub async fn process_msg_3(&mut self, msg3: RaMsg3) -> SpRaResult<(RaMsg4, Option<String>)> {
        // Integrity check
        if &msg3.g_a[..] != &self.g_a.as_ref().unwrap()[..] {
            return Err(SpRaError::IntegrityError);
        }
        if !msg3.verify_mac(self.smk.as_mut().unwrap()).is_ok() {
            return Err(SpRaError::IntegrityError);
        }

        let quote_digest: Sha256Digest = (&msg3.quote.as_ref()[368..400]).try_into().unwrap();
        if self.verification_digest.as_ref().unwrap() != &quote_digest {
            return Err(SpRaError::IntegrityError);
        }

        // Verify attestation evidence
        // TODO: use the secondary key as well
        let attestation_result = self
            .ias_client
            .verify_attestation_evidence(&msg3.quote, &self.config.primary_subscription_key)
            .await?;

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
        if mrenclave != self.sigstruct.enclavehash.as_ref()
            || mrsigner != sha256(self.sigstruct.modulus.as_ref())?.as_ref()
            || isvprodid != self.sigstruct.isvprodid
            || isvsvn != self.sigstruct.isvsvn
        {
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
        let is_enclave_trusted = (quote_status == "OK")
            || self
                .config
                .quote_trust_options
                .binary_search(&quote_status)
                .is_ok();
        let is_pse_manifest_trusted = pse_manifest_status.map(|status| {
            (status == "OK")
                || self
                    .config
                    .pse_trust_options
                    .as_ref()
                    .unwrap()
                    .binary_search(&status)
                    .is_ok()
        });

        Ok((
            RaMsg4 {
                is_enclave_trusted,
                is_pse_manifest_trusted,
                pib: attestation_result.platform_info_blob,
            },
            attestation_result.epid_pseudonym,
        ))
    }
}
