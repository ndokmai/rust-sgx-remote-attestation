pub mod error;

use std::mem::size_of;
use aesm_client::{AesmClient, QuoteInfo};
use sgx_isa::Report;
use crypto::cmac::MacTag;
use crypto::key_exchange::DHKEPublicKey;
use ra_common::msg::{Gid, Quote, PsSecPropDesc, RaMsg0, RaMsg1, RaMsg2, RaMsg3, RaMsg4};
use ra_common::Stream;
use crate::error::ClientRaError;

pub type ClientRaResult<T> = Result<T, ClientRaError>;


pub struct ClientRaContext {
    pub aesm_client: AesmClient,
    pub quote_info: QuoteInfo,
    pub g_a: Option<DHKEPublicKey>, 
}

impl ClientRaContext {
    pub fn do_attestation(mut self, mut enclave_stream: &mut impl Stream, 
                          mut sp_stream: &mut impl Stream) -> ClientRaResult<()> {
        let mut g_a: DHKEPublicKey = [0u8; size_of::<DHKEPublicKey>()];
        enclave_stream.read_exact(&mut g_a[..])?;
        self.g_a = Some(g_a);
        let _msg0 = self.get_extended_epid_group_id(); // not really using this for now
        let msg1 = self.get_msg_1();
        bincode::serialize_into(&mut sp_stream, &msg1)?;
        let msg2: RaMsg2 = bincode::deserialize_from(&mut sp_stream)?;
        let msg3 = self.process_msg_2(msg2, enclave_stream)?;
        bincode::serialize_into(&mut sp_stream, &msg3)?;
        let msg4: RaMsg4 = bincode::deserialize_from(&mut sp_stream)?;
        bincode::serialize_into(&mut enclave_stream, &msg4)?;
        if !msg4.is_enclave_trusted {
            return Err(ClientRaError::EnclaveNotTrusted);
        }
        match msg4.is_pse_manifest_trusted {
            Some(t) => if !t {
                return Err(ClientRaError::EnclaveNotTrusted);
            },
            None => {},
        }
        Ok(())
    }
    pub fn init() -> ClientRaResult<Self>  {
        let aesm_client = AesmClient::new();
        let quote_info = aesm_client.init_quote()?;
        Ok(Self {
            aesm_client, 
            quote_info,
            g_a: None,
        })
    }

    pub fn get_extended_epid_group_id(&self) -> RaMsg0 {
        RaMsg0 { exgid: 0 }
    }

    pub fn get_msg_1(&self) -> RaMsg1 {
        let mut gid: Gid = [0u8; size_of::<Gid>()];
        gid.clone_from_slice(self.quote_info.gid());
        RaMsg1 { gid, g_a: *self.g_a.as_ref().unwrap() }
    }

    pub fn process_msg_2(&self, msg2: RaMsg2, 
                         mut enclave_stream: &mut impl Stream) -> ClientRaResult<RaMsg3> {
        // send msg2 to enclave
        bincode::serialize_into(&mut enclave_stream, &msg2)?;

        // Get report for QE from enclave
        enclave_stream.write_all(self.quote_info.target_info())?;
        let mut report = vec![0u8; Report::UNPADDED_SIZE];
        enclave_stream.read_exact(&mut report[..])?;

        // Get a quote and QE report from QE and send them to enclave
        let sig_rl = match msg2.sig_rl {
            Some(sig_rl) => sig_rl.to_owned(),
            None => Vec::with_capacity(0),
        };
        let _quote = self.aesm_client.get_quote(
            &self.quote_info,
            report,
            (&msg2.spid[..]).to_owned(),
            sig_rl)?;
        enclave_stream.write_all(_quote.quote())?;
        enclave_stream.write_all(_quote.qe_report())?;

        // No PSE available yet, so this will be all 0s for now
        let ps_sec_prop = [0u8; size_of::<PsSecPropDesc>()];
        enclave_stream.write_all(&ps_sec_prop)?;

        // Read MAC for msg3 from enclave
        let mut mac = [0u8; size_of::<MacTag>()];
        enclave_stream.read_exact(&mut mac)?;

        let mut quote = [0u8; size_of::<Quote>()];
        quote.copy_from_slice(_quote.quote());

        Ok(RaMsg3{
            mac,
            g_a: *self.g_a.as_ref().unwrap(),
            ps_sec_prop,
            quote
        })
    }
}
