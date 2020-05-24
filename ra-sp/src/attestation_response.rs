use crate::error::AttestationError;
use hyper::header::{HeaderMap, HeaderValue};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sgx_crypto::certificate::X509Cert;

#[derive(Deserialize, Debug)]
pub struct AttestationResponse {
    // header
    pub advisory_url: Option<String>,
    pub advisory_ids: Option<String>,
    pub request_id: String,
    // body
    pub id: String,
    pub timestamp: String,
    pub version: u16,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
}

impl AttestationResponse {
    pub fn from_response(
        root_ca_cert: &X509Cert,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<Self, AttestationError> {
        Self::verify_response(root_ca_cert, &headers, &body[..])?;

        let body: Value = {
            let body = String::from_utf8(body).unwrap();
            serde_json::from_str(&body).unwrap()
        };

        let h = |x: &HeaderValue| x.to_str().unwrap().to_owned();
        let b = |x: &str| x.to_owned();
        Ok(Self {
            // header
            advisory_ids: headers.get("advisory-ids").map(h),
            advisory_url: headers.get("advisory-url").map(h),
            request_id: headers.get("request-id").map(h).unwrap(),
            // body
            id: body["id"].as_str().unwrap().to_owned(),
            timestamp: body["timestamp"].as_str().unwrap().to_owned(),
            version: body["version"].as_u64().unwrap() as u16,
            isv_enclave_quote_status: body["isvEnclaveQuoteStatus"].as_str().unwrap().to_owned(),
            isv_enclave_quote_body: body["isvEnclaveQuoteBody"].as_str().unwrap().to_owned(),
            revocation_reason: body["revocationReason"].as_str().map(b),
            pse_manifest_status: body["pseManifestStatus"].as_str().map(b),
            pse_manifest_hash: body["pseManifestHash"].as_str().map(b),
            platform_info_blob: body["platformInfoBlob"].as_str().map(b),
            nonce: body["nonce"].as_str().map(b),
            epid_pseudonym: body["epidPseudonym"].as_str().map(b),
        })
    }

    fn verify_response(
        root_ca_cert: &X509Cert,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), AttestationError> {
        // Split certificates
        let re = Regex::new(
            "(-----BEGIN .*-----\\n)\
                            ((([A-Za-z0-9+/]{4})*\
                              ([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\\n)+)\
                            (-----END .*-----)",
        )
        .unwrap();
        let (mut certificate, mut ca_certificate) = {
            let c = headers
                .get("x-iasreport-signing-certificate")
                .unwrap()
                .to_str()
                .unwrap();
            let c = percent_encoding::percent_decode_str(c)
                .decode_utf8()
                .unwrap();
            let c = re
                .find_iter(&c)
                .map(|m| m.as_str().to_owned())
                .collect::<Vec<String>>();
            let mut c_iter = c.into_iter();
            let mut certificate = c_iter.next().unwrap();
            certificate.push('\0');
            let certificate = X509Cert::new_from_pem(certificate.as_bytes()).unwrap();
            let mut ca_certificate = c_iter.next().unwrap();
            ca_certificate.push('\0');
            let ca_certificate = X509Cert::new_from_pem(ca_certificate.as_bytes()).unwrap();
            (certificate, ca_certificate)
        };

        // Check if the root certificate is the same as the SP-provided certificate
        if root_ca_cert != &ca_certificate {
            return Err(AttestationError::MismatchedIASRootCertificate);
        }

        // Check if the certificate is signed by root CA
        certificate
            .verify_this_certificate(&mut ca_certificate)
            .map_err(|_| AttestationError::InvalidIASCertificate)?;

        // Check if the signature is correct
        let signature = base64::decode(
            headers
                .get("x-iasreport-signature")
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        certificate
            .verify_signature(body, &signature[..])
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(())
    }
}
