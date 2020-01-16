use std::mem::size_of;
use serde::{Serialize, Deserialize};
use serde_big_array::big_array;
use sgx_crypto::signature::Signature;
use sgx_crypto::key_exchange::DHKEPublicKey;

pub type Gid = [u8; 4];
pub type Spid = [u8; 16];
pub type PsSecPropDesc = [u8; 256];
pub type Quote = [u8; 1116]; // 436 + quote.signature_len for version 2

big_array! { 
    BigArray; 
    +size_of::<DHKEPublicKey>(), size_of::<Quote>(),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RaMsg0 {
    pub exgid: u32,
}


#[derive(Serialize, Deserialize)]
pub struct RaMsg1 {
    pub gid: Gid,
    #[serde(with = "BigArray")]
    pub g_a: DHKEPublicKey 
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg2 {
    #[serde(with = "BigArray")]
    pub g_b: DHKEPublicKey,
    pub spid: Spid,
    pub quote_type: u16, /* unlinkable Quote(0) or linkable Quote(1) */
    pub signature: Signature, // Sign(g_b||g_a||spid||quote_type)
    pub sig_rl: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct PsSecPropDescInternal {
    #[serde(with = "BigArray")]
    pub inner: PsSecPropDesc,
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg3 {
    pub ps_sec_prop: Option<PsSecPropDescInternal>,
    #[serde(with = "BigArray")]
    pub quote: Quote,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RaMsg4 {
    pub is_enclave_trusted: bool,
    pub is_pse_manifest_trusted: Option<bool>,
    pub pib: Option<String>,
}
