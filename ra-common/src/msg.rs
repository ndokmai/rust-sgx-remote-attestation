use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;
use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::error::CryptoError;
use sgx_crypto::key_exchange::DHKEPublicKey;
use sgx_crypto::signature::Signature;
use std::io::Write;
use std::mem::size_of;

pub type Gid = [u8; 4];
pub type Spid = [u8; 16];
pub type PsSecPropDesc = [u8; 256];
pub type Quote = [u8; 1116]; // 436 + quote.signature_len for version 2

big_array! {
    BigArray;
    +size_of::<Quote>(),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RaMsg0 {
    pub exgid: u32,
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg1 {
    pub gid: Gid,
    pub g_a: DHKEPublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg2 {
    pub g_b: DHKEPublicKey,
    pub spid: Spid,
    pub quote_type: u16, /* unlinkable Quote(0) or linkable Quote(1) */
    pub sign_gb_ga: Signature,
    pub mac: MacTag,
    pub sig_rl: Option<Vec<u8>>,
}

impl RaMsg2 {
    pub fn new(
        smk: &mut Cmac,
        g_b: DHKEPublicKey,
        spid: Spid,
        quote_type: u16,
        sign_gb_ga: Signature,
        sig_rl: Option<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        let mut msg2 = Self {
            g_b,
            spid,
            quote_type,
            sign_gb_ga,
            mac: [0u8; size_of::<MacTag>()],
            sig_rl,
        };
        let a = msg2.get_a();
        msg2.mac = smk.sign(&a[..])?;
        Ok(msg2)
    }

    pub fn verify_mac(&self, smk: &mut Cmac) -> Result<(), CryptoError> {
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

#[derive(Serialize, Deserialize)]
pub struct PsSecPropDescInternal {
    #[serde(with = "BigArray")]
    pub inner: PsSecPropDesc,
}

#[derive(Serialize, Deserialize)]
pub struct RaMsg3 {
    pub mac: MacTag,
    pub g_a: DHKEPublicKey,
    pub ps_sec_prop: Option<PsSecPropDescInternal>,
    #[serde(with = "BigArray")]
    pub quote: Quote,
}

impl RaMsg3 {
    pub fn new(
        smk: &mut Cmac,
        g_a: DHKEPublicKey,
        ps_sec_prop: Option<PsSecPropDesc>,
        quote: Quote,
    ) -> Result<Self, CryptoError> {
        let ps_sec_prop = ps_sec_prop.map(|v| PsSecPropDescInternal { inner: v });
        let mut msg3 = Self {
            mac: [0u8; size_of::<MacTag>()],
            g_a,
            ps_sec_prop,
            quote,
        };
        let m = msg3.get_m();
        msg3.mac = smk.sign(&m[..])?;
        Ok(msg3)
    }

    pub fn verify_mac(&self, smk: &mut Cmac) -> Result<(), CryptoError> {
        let m = self.get_m();
        smk.verify(&m[..], &self.mac)
    }

    fn get_m(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.write_all(&self.g_a[..]).unwrap();
        if self.ps_sec_prop.is_some() {
            m.write_all(&self.ps_sec_prop.as_ref().unwrap().inner[..])
                .unwrap();
        }
        m.write_all(&self.quote[..]).unwrap();
        m
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RaMsg4 {
    pub is_enclave_trusted: bool,
    pub is_pse_manifest_trusted: Option<bool>,
    pub pib: Option<String>,
}
