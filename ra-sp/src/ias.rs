use std::io::Write;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use hyper::{Client, client::HttpConnector, Body, Request, StatusCode};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::body::HttpBody as _;
use hyper_tls::HttpsConnector;
use ra_common::msg::{Gid, Quote};
use crypto::signature::X509Cert;

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const SIG_RL_PATH: &str = "/attestation/v3/sigrl/";
const REPORT_PATH: &str = "/attestation/v3/report";

//#[derive(Deserialize, Debug, PartialEq)]
//pub enum QuoteStatus {
    //Ok,
    //GroupOutOfDate,
    //ConfigurationNeeded,
    //GroupRevoked,
    //Other(String),
//}

//impl std::str::FromStr for QuoteStatus {
    //type Err = ();
    //fn from_str(s: &str) -> Result<Self, Self::Err> {
        //match s {
            //"OK" => Ok(Self::Ok),
            //"GROUP_OUT_OF_DATE" => Ok(Self::GroupOutOfDate),
            //"CONFIGURATION_NEEDED" => Ok(Self::ConfigurationNeeded),
            //"GROUP_REVOKED" => Ok(Self::GroupRevoked),
            //_ => Ok(Self::Other(s.to_owned())) 
        //}
    //}
//} 

//#[derive(Deserialize, Debug, PartialEq)]
//pub enum PseManifestStatus {
    //Ok,
    //Invalid,
    //Other(String)
//}

//impl std::str::FromStr for PseManifestStatus {
    //type Err = ();
    //fn from_str(s: &str) -> Result<Self, Self::Err> {
        //match s {
            //"OK" => Ok(Self::Ok),
            //"INVALID" => Ok(Self::Invalid),
            //_ => Ok(Self::Other(s.to_owned())),
        //}
    //}
//} 

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
    pub async fn from_response(headers: &HeaderMap, body: Vec<u8>) -> Result<Self, IasError> {
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
            isv_enclave_quote_status: body["isvEnclaveQuoteStatus"].as_str().unwrap()
                .to_owned(),
            isv_enclave_quote_body: body["isvEnclaveQuoteBody"].as_str().unwrap()
                .to_owned(),
            revocation_reason: body["revocationReason"].as_str().map(b),
            pse_manifest_status: body["pseManifestStatus"].as_str().map(b),
            pse_manifest_hash: body["pseManifestHash"].as_str().map(b),
            platform_info_blob: body["platformInfoBlob"].as_str().map(b),
            nonce: body["nonce"].as_str().map(b),
            epid_pseudonym: body["epidPseudonym"].as_str().map(b),
        })
    }

}

#[derive(Debug)]
pub enum IasError {
    IO(std::io::Error),
    Hyper(hyper::error::Error),
    Http(http::Error),
    SigRL(StatusCode),
    Attestation(StatusCode),
    Signature(crypto::signature::SigError),
    Integrity
}

impl std::convert::From<std::io::Error> for IasError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<hyper::error::Error> for IasError {
    fn from(e: hyper::error::Error) -> Self { Self::Hyper(e) }
}

impl std::convert::From<http::Error> for IasError {
    fn from(e: http::Error) -> Self { Self::Http(e) }
}

impl std::convert::From<crypto::signature::SigError> for IasError {
    fn from(e: crypto::signature::SigError) -> Self { Self::Signature(e) }
}

pub struct IasClient {
    https_client: Client<HttpsConnector<HttpConnector>>, 
    root_ca_cert: X509Cert,
}


impl IasClient {
    pub fn new(root_ca_cert: X509Cert) -> Self {
        Self {
            https_client: Client::builder()
            .build::<_, hyper::Body>(HttpsConnector::new()),
            root_ca_cert
        }
    }
    pub async fn get_sig_rl(&self, gid: &Gid, 
                            subscription_key: &str) 
        -> Result<Option<Vec<u8>>, IasError> {
            let uri = format!("{}{}{:02x}{:02x}{:02x}{:02x}", BASE_URI, SIG_RL_PATH, 
                              gid[0], gid[1], gid[2], gid[3]);
            let req = Request::get(uri)
                .header("Ocp-Apim-Subscription-Key", subscription_key)
                .body(Body::empty())?;
            let mut resp = self.https_client.request(req).await?;
            if resp.status().as_u16() != 200 {
                return Err(IasError::SigRL(resp.status()));
            }
            if resp.headers().get("content-length").unwrap() == "0" {
                return Ok(None);
            }
            let mut sig_rl = Vec::new();
            while let Some(chunk) = resp.body_mut().data().await {
                sig_rl.write_all(&chunk?)?;
            }
            Ok(Some(sig_rl))
        }

    pub async fn verify_attestation(&self,
                                    quote: &Quote, 
                                    subscription_key: &str) 
        -> Result<AttestationResponse, IasError> {
            let uri = format!("{}{}", BASE_URI, REPORT_PATH);
            let quote_base64 = base64::encode(&quote[..]);
            let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64);
            let req = Request::post(uri)
                .header("Content-type","application/json")
                .header("Ocp-Apim-Subscription-Key", subscription_key)
                .body(Body::from(body))?;
            let mut resp = self.https_client.request(req).await?;
            if resp.status().as_u16() != 200 {
                return Err(IasError::Attestation(resp.status()));
            }
            let mut body = Vec::new();
            while let Some(chunk) = resp.body_mut().data().await {
                body.write_all(&chunk?)?;
            }
            self.verify_response(resp.headers(), &body[..])?;

            Ok(AttestationResponse::from_response(resp.headers(), body).await?)
        }

    fn verify_response(&self, headers: &HeaderMap, 
                       body: &[u8]) -> Result<(), IasError> {
        let re = Regex::new("(-----BEGIN .*-----\\n)\
                            ((([A-Za-z0-9+/]{4})*\
                              ([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\\n)+)\
                            (-----END .*-----)").unwrap();
        let (certificate, ca_certificate) =  {
            let c = headers.get("x-iasreport-signing-certificate")
                .unwrap().to_str().unwrap();
            let c = percent_encoding::percent_decode_str(c).decode_utf8().unwrap();
            let c = re.find_iter(&c)
                .map(|m| m.as_str().to_owned())
                .collect::<Vec<String>>();
            let mut c_iter = c.into_iter();
            let certificate = c_iter.next().unwrap();
            let certificate = X509Cert::new_from_pem(&certificate)?;
            let ca_certificate = c_iter.next().unwrap();
            let ca_certificate = X509Cert::new_from_pem(&ca_certificate)?;
            (certificate, ca_certificate)
        };
        if self.root_ca_cert != ca_certificate {
            return Err(IasError::Integrity);
        }
        certificate.verify_with_ca(&ca_certificate)?;
        let verification_key = certificate.get_verification_key();
        let signature = base64::decode(
            headers.get("x-iasreport-signature").unwrap().to_str().unwrap()).unwrap();
        verification_key.verify(body, &signature[..])?;
        Ok(())
    }
}
