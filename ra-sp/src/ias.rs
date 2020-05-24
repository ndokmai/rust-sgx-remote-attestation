use crate::attestation_response::AttestationResponse;
use crate::error::{AttestationError, IasError};
use hyper::body::HttpBody as _;
use hyper::{client::HttpConnector, Body, Client, Request};
use hyper_tls::HttpsConnector;
use ra_common::msg::{Gid, Quote};
use sgx_crypto::certificate::X509Cert;
use std::io::Write;

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const SIG_RL_PATH: &str = "/attestation/v3/sigrl/";
const REPORT_PATH: &str = "/attestation/v3/report";

pub struct IasClient {
    https_client: Client<HttpsConnector<HttpConnector>>,
    root_ca_cert: X509Cert,
}

impl IasClient {
    pub fn new(root_ca_cert: X509Cert) -> Self {
        Self {
            https_client: Client::builder().build::<_, hyper::Body>(HttpsConnector::new()),
            root_ca_cert,
        }
    }

    pub async fn get_sig_rl(
        &self,
        gid: &Gid,
        subscription_key: &str,
    ) -> Result<Option<Vec<u8>>, IasError> {
        let uri = format!(
            "{}{}{:02x}{:02x}{:02x}{:02x}",
            BASE_URI, SIG_RL_PATH, gid[0], gid[1], gid[2], gid[3]
        );
        let req = Request::get(uri)
            .header("Ocp-Apim-Subscription-Key", subscription_key)
            .body(Body::empty())
            .unwrap();
        let mut resp = self.https_client.request(req).await?;
        if resp.status().as_u16() != 200 {
            return Err(IasError::SigRLError(resp.status()));
        }
        if resp.headers().get("content-length").unwrap() == "0" {
            return Ok(None);
        }
        let mut sig_rl = Vec::new();
        while let Some(chunk) = resp.body_mut().data().await {
            sig_rl.write_all(&chunk.unwrap()).unwrap();
        }
        Ok(Some(sig_rl))
    }

    pub async fn verify_attestation_evidence(
        &self,
        quote: &Quote,
        subscription_key: &str,
    ) -> Result<AttestationResponse, IasError> {
        let uri = format!("{}{}", BASE_URI, REPORT_PATH);
        let quote_base64 = base64::encode(&quote[..]);
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64);
        let req = Request::post(uri)
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", subscription_key)
            .body(Body::from(body))
            .unwrap();
        let mut resp = self.https_client.request(req).await?;
        if resp.status().as_u16() != 200 {
            return Err(IasError::Attestation(AttestationError::Connection(
                resp.status(),
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.body_mut().data().await {
            body.write_all(&chunk.unwrap()).unwrap();
        }

        AttestationResponse::from_response(&self.root_ca_cert, resp.headers(), body)
            .map_err(|e| IasError::Attestation(e))
    }
}
