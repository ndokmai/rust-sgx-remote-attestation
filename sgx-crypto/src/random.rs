pub use mbedtls::rng::EntropyCallback;

#[cfg(not(target_env = "sgx"))]
pub fn entropy_new<'a>() -> mbedtls::rng::OsEntropy<'a> {
    mbedtls::rng::OsEntropy::new()
}

#[cfg(target_env = "sgx")]
pub struct Rng {
    pub inner: mbedtls::rng::Rdrand,
}

#[cfg(target_env = "sgx")]
impl Rng {
    pub fn new() -> Self {
        Self {
            inner: mbedtls::rng::Rdrand,
        }
    }
}

#[cfg(not(target_env = "sgx"))]
pub struct Rng<'a> {
    pub inner: mbedtls::rng::CtrDrbg<'a>,
}

#[cfg(not(target_env = "sgx"))]
impl<'a> Rng<'a> {
    pub fn new(source: &'a mut impl EntropyCallback) -> super::Result<Self> {
        Ok(Self {
            inner: mbedtls::rng::CtrDrbg::new(source, None)?,
        })
    }
}
