use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, HandshakeContext};
use mbedtls::Result;

use super::random::Rng;

type Callback = Box<dyn FnMut(&mut HandshakeContext, &str) -> Result<()>>;

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
}

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
}
