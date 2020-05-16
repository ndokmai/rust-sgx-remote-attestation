use std::path::Path;
use std::io::Read;
use std::fs::File;
use mbedtls::pk::Pk;
use super::digest::{sha256, SHA256_TYPE};
use super::random::Rng;

pub type Signature = Vec<u8>;

pub struct VerificationKey {
    inner: Pk
}

impl VerificationKey {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    /// When calling on PEM-encoded data, key must be NULL-terminated
    pub fn new(public_key: &[u8]) -> super::Result<Self> {
        let inner = Pk::from_public_key(public_key)?;
        Ok(Self { inner })
    }

    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    pub fn new_from_file(public_key_path: &Path) -> super::Result<Self> {
        let mut file = File::open(public_key_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if public_key_path.extension().unwrap() == "pem" {
            buf.push(0);
        }
        Self::new(&buf[..])
    }

    pub fn verify(&mut self, message: &[u8], signature: &[u8]) -> super::Result<()> {
        let hash = sha256(message)?;
        self.inner.verify(SHA256_TYPE, &hash[..], signature)?;
        Ok(())
    }

    //pub fn as_ref(&self) -> &[u8] {
    //}
}

pub struct SigningKey {
    inner: Pk
}
impl SigningKey {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    /// When calling on PEM-encoded data, key must be NULL-terminated
    pub fn new(private_key: &[u8], password: Option<&[u8]>) -> super::Result<Self> {
        let inner = Pk::from_private_key(private_key, password)?;
        Ok(Self { inner })
    }

    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    pub fn new_from_file(private_key_path: &Path, password: Option<&[u8]>) -> 
        super::Result<Self> {
            let mut file = File::open(private_key_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            if private_key_path.extension().unwrap() == "pem" {
                buf.push(0);
            }
            Self::new(&buf[..], password)
        }

    pub fn sign(&mut self, message: &[u8], rng: &mut Rng) -> 
        super::Result<Signature> {
            let hash = sha256(message)?;
            let sig_len =  self.inner.rsa_public_modulus()?.byte_length()?;
            let mut signature = vec![0u8; sig_len];
            self.inner.sign(SHA256_TYPE, &hash[..], &mut signature[..], &mut rng.inner)?;
            Ok(signature)
        }
}

//// Adapted from Ring's documentation https://briansmith.org/rustdoc/ring/signature/index.html
////use std::path::Path;
//use std::io::Read;
////use std::fs::File;
//use ring::signature;
//use untrusted::Input;
//use crate::random::RandomState;
//use crate::pem_parser::pem_to_der;

//static SIG_ALG: &signature::RsaParameters = &signature::RSA_PKCS1_2048_8192_SHA256;
//static PADDING_ALG: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;

//pub type Signature = Vec<u8>; // variable length, depending on RSA parameters

//#[derive(Debug)]
//pub enum SigError {
   //IO(std::io::Error),
   //BadPrivateKey,
   //BadPublicKey,
   //BadSignature,
   //OutOfMemory
//}

//pub struct VerificationKey {
    //key: Vec<u8>,
//}

//impl VerificationKey {
    //pub fn new_from_der(public_key_der: &[u8]) -> Result<Self, SigError> {
        //let mut key = vec![0u8; public_key_der.len()];
        //(&mut key[..]).copy_from_slice(public_key_der);
        //Ok(Self { key })
    //}

    //pub fn new_from_pem(public_key_pem: &str) -> Result<Self, SigError> {
        //let pem = pem_to_der(public_key_pem).map_err(|_| SigError::BadPublicKey)?;
        //Self::new_from_der(&pem[..])
    //}

    //pub fn new_from_der_file(public_key_der: &Path) ->  Result<Self, SigError> {
        //Ok(Self { key: read_file(public_key_der)? })
    //}

    //pub fn new_from_pem_file(public_key_pem: &Path) -> Result<Self, SigError> {
        //let pem = read_file(public_key_pem)?;
        //Self::new_from_pem(&String::from_utf8(pem).map_err(|_| SigError::BadPublicKey)?)
    //}

    //pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigError> {
        //signature::verify(SIG_ALG, 
                          //Input::from(&self.key[..]), 
                          //Input::from(message), 
                          //Input::from(signature))
            //.map_err(|_| SigError::BadSignature)
    //}

    //pub fn as_ref(&self) -> &[u8] {
        //&self.key[..]
    //}
//}

//pub struct SigningKey {
    //key_pair: signature::RsaKeyPair,
//}

//impl SigningKey {
    //pub fn new_from_der_file(private_key_der: &Path) ->  Result<Self, SigError> {
        //let private_key_der = read_file(&private_key_der)?;
        //let private_key_der = Input::from(&private_key_der[..]);
        //let key_pair = signature::RsaKeyPair::from_der(private_key_der)
            //.map_err(|_| SigError::BadPrivateKey)?;
        //Ok( Self { key_pair } )
    //}

    //pub fn new_from_pem_file(private_key_pem: &Path) ->  Result<Self, SigError> {
        //let private_key_pem = read_file(&private_key_pem)?;
        //let private_key_pem = String::from_utf8(private_key_pem)
            //.map_err(|_| SigError::BadPrivateKey)?;
        //let private_key_der = pem_to_der(&private_key_pem)
            //.map_err(|_| SigError::BadPrivateKey)?;
        //let private_key_der = Input::from(&private_key_der[..]);
        //let key_pair = signature::RsaKeyPair::from_der(private_key_der)
            //.map_err(|_| SigError::BadPrivateKey)?;
        //Ok( Self { key_pair } )
    //}

    //pub fn sign(&self, msg: &[u8], rng: &RandomState) 
        //-> Result<Signature, SigError> {
            //let mut signature = vec![0; self.key_pair.public_modulus_len()];
            //self.key_pair.sign(PADDING_ALG, rng.inner(), msg, &mut signature)
                //.map_err(|_| SigError::OutOfMemory)?;
            //Ok(signature)
        //}
//}

//fn read_file(path: &Path) -> Result<Vec<u8>, SigError> {
    //let mut file = File::open(path).map_err(|e| SigError::IO(e))?;
    //let mut contents: Vec<u8> = Vec::new();
    //file.read_to_end(&mut contents).map_err(|e| SigError::IO(e))?;
    //Ok(contents)
//}
