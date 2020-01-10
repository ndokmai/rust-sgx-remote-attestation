// Adapted from Ring's documentation https://briansmith.org/rustdoc/ring/signature/index.html
use std::path::Path;
use std::io::Read;
use std::fs::File;
use ring::signature;
use x509_parser::x509::X509Certificate;
use untrusted::Input;
use webpki::trust_anchor_util::cert_der_as_trust_anchor;
use crate::random::RandomState;
use crate::pem_parser::pem_to_der;

static SIG_ALG: &signature::RsaParameters = &signature::RSA_PKCS1_2048_8192_SHA256;
static PADDING_ALG: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;
pub type Signature = Vec<u8>; // variable lengths, depending on RSA parameters

#[derive(Debug)]
pub enum SigError {
   IO(std::io::Error),
   BadPrivateKey,
   OOM,
   BadSignature,
   PEMDecode(base64::DecodeError),
   X509ParseError,
   Certificate(webpki::Error),
}

#[derive(PartialEq, Debug)]
pub struct X509Cert {
    cert: Vec<u8>,
}

impl X509Cert {
    pub fn new_from_pem_file(x509_pem: &Path) -> Result<Self, SigError> {
        let pem = read_file(x509_pem)?;
        Self::new_from_pem(&String::from_utf8(pem).unwrap())
    }

    pub fn new_from_der(x509_der: &[u8]) -> Result<Self, SigError> {
        Ok(Self {
            cert: match Self::_parse(x509_der) {
                Ok(_) => x509_der.to_owned(),
                Err(e) => return Err(e),
            },
        })
    }

    pub fn new_from_pem(x509_pem: &str) -> Result<Self, SigError> {
        let der = pem_to_der(x509_pem).map_err(|e| SigError::PEMDecode(e))?;
        Self::new_from_der(&der[..])
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.cert[..]
    }

    pub fn get_verification_key(&self) -> VerificationKey {
        let cert = self.parse().unwrap();
        VerificationKey::new_from_der(
            cert.tbs_certificate.subject_pki.subject_public_key.as_ref()).unwrap()
    }
    pub fn get_signature(&self) -> Signature {
        let cert = self.parse().unwrap();
        cert.signature_value.as_ref().to_owned()
    }

    pub fn verify_with_ca(&self, ca_cert: &Self) -> Result<(), SigError> {
        static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
            &webpki::RSA_PKCS1_2048_8192_SHA256,
            &webpki::RSA_PKCS1_2048_8192_SHA384,
            &webpki::RSA_PKCS1_2048_8192_SHA512,
            &webpki::RSA_PKCS1_3072_8192_SHA384,
        ];
        let anchors = vec![cert_der_as_trust_anchor(Input::from(ca_cert.as_ref())).unwrap()];
        webpki::TLSServerTrustAnchors(&anchors);
        let anchors = webpki::TLSServerTrustAnchors(&anchors);
        let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);
        let cert = webpki::EndEntityCert::from(Input::from(self.as_ref())).unwrap();
        cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
            .map_err(|e| SigError::Certificate(e))
    }

    pub fn parse<'a>(&'a self) -> Result<X509Certificate<'a>, SigError> {
        Self::_parse(&self.cert[..])
    }

    fn _parse<'a>(x509_der: &'a [u8]) -> Result<X509Certificate<'a>, SigError> {
        match x509_parser::parse_x509_der(x509_der) {
            Ok((_, cert)) => Ok(cert),
            Err(_) => Err(SigError::X509ParseError),
        }
    }
}

pub struct VerificationKey {
    key: Vec<u8>,
}

impl VerificationKey {
    pub fn new_from_der_file(public_key_der: &Path) ->  Result<Self, SigError> {
        Ok(Self { key: read_file(public_key_der)? })
    }

    pub fn new_from_pem_file(public_key_pem: &Path) -> Result<Self, SigError> {
        let pem = read_file(public_key_pem)?;
        Self::new_from_pem(&String::from_utf8(pem).unwrap())
    }

    pub fn new_from_pem(public_key_pem: &str) -> Result<Self, SigError> {
        let pem = pem_to_der(public_key_pem).map_err(|e| SigError::PEMDecode(e))?;
        Self::new_from_der(&pem[..])
    }

    pub fn new_from_der(public_key_der: &[u8]) -> Result<Self, SigError> {
        let mut key = vec![0u8; public_key_der.len()];
        (&mut key[..]).copy_from_slice(public_key_der);
        Ok(Self { key })
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.key[..]
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigError> {
        signature::verify(SIG_ALG, 
                          Input::from(&self.key[..]), 
                          Input::from(message), 
                          Input::from(signature))
            .map_err(|_| SigError::BadSignature)
    }
}

pub struct SigningKey {
    key_pair: signature::RsaKeyPair,
}

impl SigningKey {
    pub fn new_from_der_file(private_key_der: &Path) ->  Result<Self, SigError> {
        let private_key_der = read_file(&private_key_der)?;
        let private_key_der = Input::from(&private_key_der[..]);
        let key_pair = signature::RsaKeyPair::from_der(private_key_der)
            .map_err(|_| SigError::BadPrivateKey)?;
        Ok( Self { key_pair } )
    }

    pub fn new_from_pem_file(private_key_pem: &Path) ->  Result<Self, SigError> {
        let private_key_pem = read_file(&private_key_pem)?;
        let private_key_pem = String::from_utf8(private_key_pem).unwrap();
        let private_key_der = pem_to_der(&private_key_pem).unwrap();
        let private_key_der = Input::from(&private_key_der[..]);
        let key_pair = signature::RsaKeyPair::from_der(private_key_der)
            .map_err(|_| SigError::BadPrivateKey)?;
        Ok( Self { key_pair } )
    }

    pub fn sign(&self, msg: &[u8], rng: &RandomState) 
        -> Result<Signature, SigError> {
            let mut signature = vec![0; self.key_pair.public_modulus_len()];
            self.key_pair.sign(PADDING_ALG, rng.inner(), msg, &mut signature)
                .map_err(|_| SigError::OOM)?;
            Ok(signature)
        }
}

fn read_file(path: &Path) -> Result<Vec<u8>, SigError> {
    let mut file = File::open(path).map_err(|e| SigError::IO(e))?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| SigError::IO(e))?;
    Ok(contents)
}
