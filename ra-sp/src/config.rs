use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct SpConfig {
    pub linkable: bool,
    pub random_nonce: bool,
    pub use_platform_service: bool,
    pub spid: String,
    pub primary_subscription_key: String,
    pub secondary_subscription_key: String,
    pub quote_trust_options: Vec<String>,
    pub pse_trust_options: Option<Vec<String>>,
    pub sp_private_key_pem_path: String,
    pub ias_root_cert_pem_path: String,
    pub sigstruct_path: String,
}
