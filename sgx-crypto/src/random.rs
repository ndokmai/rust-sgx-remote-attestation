#[cfg(target_env = "sgx")]
mod inner {
    use mbedtls::rng::Rdrand;
    pub struct Rng {
        pub inner: Rdrand,
    }

    impl Rng {
        pub fn new() -> Self {
            Self { inner: Rdrand }
        }
    }
}

#[cfg(not(target_env = "sgx"))]
mod inner {
    use mbedtls::rng::OsEntropy;
    use std::pin::Pin;
    pub struct Rng<'a> {
        pub inner: mbedtls::rng::CtrDrbg<'a>,
        _entropy: Pin<Box<OsEntropy<'a>>>,
    }

    impl<'a> Rng<'a> {
        pub fn new() -> super::super::Result<Self> {
            let mut entropy = Box::pin(OsEntropy::new());
            let entropy_ptr: *mut _ = &mut *entropy;
            unsafe {
                Ok(Self {
                    _entropy: entropy,
                    inner: mbedtls::rng::CtrDrbg::new(&mut *entropy_ptr, None)?,
                })
            }
        }
    }
}

pub use inner::*;
