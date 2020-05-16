use mbedtls::hash; 

const SHA256DIGEST_LEN: usize = 32;
pub const SHA256_TYPE: hash::Type = hash::Type::Sha256;
pub type Sha256Digest = [u8; SHA256DIGEST_LEN];

pub fn sha256(data: &[u8]) -> super::Result<Sha256Digest> {
    let mut digest = [0u8; SHA256DIGEST_LEN];
    hash::Md::hash(SHA256_TYPE, data, &mut digest[..])?;
    Ok(digest)
}

//use ring::digest;
//use std::convert::TryInto;

//const SHA256DIGEST_LEN: usize = 32;
//pub type Sha256Digest = [u8; SHA256DIGEST_LEN];

//pub fn sha256(data: &[u8]) -> Sha256Digest {
    //let digest = digest::digest(&digest::SHA256, data);
    //digest.as_ref().try_into().unwrap()
//}
