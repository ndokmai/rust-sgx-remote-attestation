use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, HandshakeContext};
use mbedtls::Result;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;

use super::random::Rng;

pub type Callback = Box<dyn FnMut(&mut HandshakeContext, &str) -> Result<()>>;

#[cfg(target_env = "sgx")]
pub mod server {
    use super::*;
    pub fn callback(psk: &[u8]) -> Callback {
        let psk = psk.to_owned();
        Box::new(move |ctx: &mut HandshakeContext, _: &str| ctx.set_psk(psk.as_ref()))
    }

    pub fn config<'a: 'c, 'b: 'c, 'c>(rng: &'a mut Rng, callback: &'b mut Callback) -> Config<'c> {
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng.inner));
        config.set_psk_callback(callback);
        config
    }

    pub fn context<'a>(config: &'a Config) -> Result<Context<'a>> {
        Context::new(&config)
    }

    pub struct ServerTlsPskContext<'a> {
        inner: Context<'a>,
        _config: Pin<Box<Config<'a>>>,
        _callback: Pin<Box<Callback>>,
        _rng: Pin<Box<Rng>>,
        _psk: Pin<Box<[u8; 16]>>,
    }

    impl<'a> ServerTlsPskContext<'a> {
        pub fn new<'b: 'a>(psk: [u8; 16]) -> Self {
            unsafe {
                let mut rng = Box::pin(Rng::new());
                let psk = Box::pin(psk);
                let psk_ptr: *const _ = &*psk;
                let mut callback = Box::pin(callback(&*psk_ptr));
                let rng_ptr: *mut _ = &mut *rng;
                let callback_ptr: *mut _ = &mut *callback;
                let config = Box::pin(config(&mut *rng_ptr, &mut *callback_ptr));
                let config_ptr: *const _ = &*config;
                let context = context(&*config_ptr).unwrap();
                Self {
                    inner: context,
                    _config: config,
                    _callback: callback,
                    _rng: rng,
                    _psk: psk,
                }
            }
        }
    }

    impl<'a> Deref for ServerTlsPskContext<'a> {
        type Target = Context<'a>;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> DerefMut for ServerTlsPskContext<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
}

#[cfg(not(target_env = "sgx"))]
pub mod client {
    use super::*;

    pub fn config<'a: 'c, 'b: 'c, 'c>(rng: &'a mut Rng, psk: &'b [u8]) -> Result<Config<'c>> {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng.inner));
        config.set_psk(psk, "Client_identity")?;
        Ok(config)
    }

    pub fn context<'a>(config: &'a Config) -> Result<Context<'a>> {
        Context::new(&config)
    }

    pub struct ClientTlsPskContext<'a> {
        inner: Context<'a>,
        _config: Pin<Box<Config<'a>>>,
        _rng: Pin<Box<Rng<'a>>>,
        _psk: Pin<Box<[u8; 16]>>,
    }

    impl<'a> ClientTlsPskContext<'a> {
        pub fn new<'b: 'a>(psk: [u8; 16]) -> Self {
            unsafe {
                let mut rng = Box::pin(Rng::new().unwrap());
                let psk = Box::pin(psk);
                let psk_ptr: *const _ = &*psk;
                let rng_ptr: *mut _ = &mut *rng;
                let config = Box::pin(config(&mut *rng_ptr, &*psk_ptr).unwrap());
                let config_ptr: *const _ = &*config;
                let context = context(&*config_ptr).unwrap();
                Self {
                    inner: context,
                    _config: config,
                    _rng: rng,
                    _psk: psk,
                }
            }
        }
    }

    impl<'a> Deref for ClientTlsPskContext<'a> {
        type Target = Context<'a>;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> DerefMut for ClientTlsPskContext<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
}
