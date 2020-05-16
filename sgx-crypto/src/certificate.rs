use std::fs::File;
use std::io::Read;
use std::path::Path;
use mbedtls::x509::Certificate;
use super::digest::{sha256, SHA256_TYPE};

#[derive(Debug)]
pub struct X509Cert {
    inner: Certificate
}

impl X509Cert {
    pub fn new_from_der(x509_der: &[u8]) -> super::Result<Self> {
        let inner = Certificate::from_der(x509_der)?;
        Ok(Self { inner })
    }

    /// Input must be NULL-terminated
    pub fn new_from_pem(x509_pem: &[u8]) -> super::Result<Self> {
        let inner = Certificate::from_pem(x509_pem)?;
        Ok(Self { inner })
    }

    pub fn new_from_der_file(x509_der_path: &Path) -> super::Result<Self> {
        let mut file = File::open(x509_der_path)?;
        let mut buf = Vec::new(); 
        file.read_to_end(&mut buf)?;
        Self::new_from_pem(&buf[..])
    }

    pub fn new_from_pem_file(x509_pem_path: &Path) -> super::Result<Self> {
        let mut file = File::open(x509_pem_path)?;
        let mut buf = Vec::new(); 
        file.read_to_end(&mut buf)?;
        buf.push(0);
        Self::new_from_pem(&buf[..])
    }

    pub fn verify_this_certificate(&mut self, trust_ca: &mut Self) -> super::Result<()> {
        self.inner.verify(&mut trust_ca.inner, None)?;
        Ok(())
    }

    pub fn verify_signature(&mut self, message: &[u8], signature: &[u8]) 
        -> super::Result<()> {
            let hash = sha256(message)?;
            self.inner.public_key_mut().verify(SHA256_TYPE, &hash[..], signature)?;
            Ok(())
    }
}

impl PartialEq for X509Cert {
    fn eq(&self, other: &Self) -> bool { 
        self.inner.as_der() == other.inner.as_der()
    }

}

////use std::fs::File;
////use std::io::Read;
////use std::path::Path;
//use x509_parser::x509::X509Certificate;
//use webpki::trust_anchor_util::cert_der_as_trust_anchor;
//use untrusted::Input;
//use crate::pem_parser::pem_to_der;
//use crate::signature::VerificationKey;

//static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    //&webpki::RSA_PKCS1_2048_8192_SHA256,
//];

//#[derive(Debug)]
//pub enum CertError {
    //IO(std::io::Error),
    //BadCertificate,
    //UnauthorizedCertificate,
//}

//#[derive(PartialEq, Debug)]
//pub struct X509Cert {
    //cert: Vec<u8>,
//}

//impl X509Cert {
    //pub fn new_from_der(x509_der: &[u8]) -> Result<Self, CertError> {
        //let _check = Self::parse(x509_der).map_err(|_| CertError::BadCertificate)?;
        //let _check =  VerificationKey::new_from_der(
            //_check.tbs_certificate.subject_pki.subject_public_key.as_ref())
            //.map_err(|_| CertError::BadCertificate)?;
        //Ok(Self {
            //cert: x509_der.to_owned(),
        //})
    //}

    //pub fn new_from_pem(x509_pem: &str) -> Result<Self, CertError> {
        //let der = pem_to_der(x509_pem).map_err(|_| CertError::BadCertificate)?;
        //Self::new_from_der(&der[..])
    //}

    //pub fn new_from_pem_file(x509_pem: &Path) -> Result<Self, CertError> {
        //let pem = read_file(x509_pem)?;
        //Self::new_from_pem(&String::from_utf8(pem)
                           //.map_err(|_| CertError::BadCertificate)?)
    //}

    //pub fn get_verification_key(&self) -> VerificationKey {
        //let cert = Self::parse(&self.cert[..]).unwrap();
        //VerificationKey::new_from_der(
            //cert.tbs_certificate.subject_pki.subject_public_key.as_ref()).unwrap()
    //}

    //pub fn verify_cert(&self, immediate_cert: &Self) -> Result<(), CertError> {
        //let anchors = vec![
            //cert_der_as_trust_anchor(Input::from(immediate_cert.as_ref())).unwrap()
        //];
        //let anchors = webpki::TLSServerTrustAnchors(&anchors);
        //let time = webpki::Time::from_seconds_since_unix_epoch(1492441716);
        //let cert = webpki::EndEntityCert::from(Input::from(self.as_ref())).unwrap();
        //cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
            //.map_err(|_| CertError::UnauthorizedCertificate)
    //}

    //pub fn as_ref(&self) -> &[u8] {
        //&self.cert[..]
    //}

    //fn parse<'a>(x509_der: &'a [u8]) -> Result<X509Certificate<'a>, CertError> {
        //match x509_parser::parse_x509_der(x509_der) {
            //Ok((_, cert)) => Ok(cert),
            //Err(_) => Err(CertError::BadCertificate),
        //}
    //}
//}

//fn read_file(path: &Path) -> Result<Vec<u8>, CertError> {
    //let mut file = File::open(path).map_err(|e| CertError::IO(e))?;
    //let mut contents: Vec<u8> = Vec::new();
    //file.read_to_end(&mut contents).map_err(|e| CertError::IO(e))?;
    //Ok(contents)
//}
