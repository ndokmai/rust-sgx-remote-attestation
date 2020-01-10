use std::io::Write;
use std::mem::size_of;
use serde::{Serialize, Deserialize};
use serde_big_array::big_array;
use byteorder::{WriteBytesExt, LittleEndian};
use crypto::key_exchange::DHKEPublicKey;
use crypto::cmac::{Cmac, MacTag};
use crypto::signature::Signature;

big_array! { 
    BigArray; 
    +65, 1116,
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg0 {
    pub exgid: u32,
}

pub type Gid = [u8; 4];

#[derive(Serialize, Deserialize)]
pub struct RaMsg1 {
    pub gid: Gid,
    #[serde(with = "BigArray")]
    pub g_a: DHKEPublicKey 
}

pub type Spid = [u8; 16];

#[derive(Serialize, Deserialize)]
pub struct RaMsg2 {
    #[serde(with = "BigArray")]
    pub g_b: DHKEPublicKey,
    pub spid: Spid,
    pub quote_type: u16, /* unlinkable Quote(0) or linkable Quote(1) */
    pub sign_gb_ga: Signature, 
    pub mac: MacTag, 
    pub sig_rl: Option<Vec<u8>>,
}

impl RaMsg2 {
    pub fn new(smk: &Cmac, 
               g_b: DHKEPublicKey, 
               spid: Spid, 
               quote_type: u16,
               sign_gb_ga: Signature, 
               sig_rl: Option<Vec<u8>>) -> Self {
        let mut msg2 = Self {
            g_b,
            spid,
            quote_type,
            sign_gb_ga,
            mac: [0u8; size_of::<MacTag>()],
            sig_rl,
        };
        let a = msg2.get_a();
        msg2.mac = smk.sign(&a[..]);
        msg2
    }

    pub fn verify_mac(&self, smk: &Cmac) -> bool {
        let a = self.get_a();
        smk.verify(&a[..], &self.mac)
    }

    fn get_a(&self) -> Vec<u8> {
        let mut a = Vec::new();
        a.write_all(&self.g_b[..]).unwrap();
        a.write_all(&self.spid[..]).unwrap();
        a.write_u16::<LittleEndian>(self.quote_type).unwrap();
        a.write_all(&self.sign_gb_ga[..]).unwrap();
        a
    }
}

pub type PsSecPropDesc = [u8; 256];
pub type Quote = [u8; 1116]; // 436 + quote.signature_len for version 2

#[derive(Serialize, Deserialize)]
pub struct RaMsg3 {
    pub mac: MacTag,
    #[serde(with = "BigArray")]
    pub g_a: DHKEPublicKey,
    #[serde(with = "BigArray")]
    pub ps_sec_prop: PsSecPropDesc,
    #[serde(with = "BigArray")]
    pub quote: Quote,
}

impl RaMsg3 {
    pub fn new(smk: &Cmac,
               g_a: DHKEPublicKey, 
               ps_sec_prop: PsSecPropDesc,
               quote: Quote) -> Self {
        let mut msg3 = Self {
            mac: [0u8; size_of::<MacTag>()],
            g_a,
            ps_sec_prop,
            quote,
        };
        let m = msg3.get_m();
        msg3.mac = smk.sign(&m[..]);
        msg3
    }

    pub fn verify_mac(&self, smk: &Cmac) -> bool {
        let m = self.get_m();
        smk.verify(&m[..], &self.mac)
    }

    fn get_m(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.write_all(&self.g_a[..]).unwrap();
        m.write_all(&self.ps_sec_prop[..]).unwrap();
        m.write_all(&self.quote[..]).unwrap();
        m
    }
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg4 {
    pub is_enclave_trusted: bool,
    pub is_pse_manifest_trusted: Option<bool>,
    pub pib: Option<String>,
}
