use ring::digest;

pub type Sha256Digest = [u8; 32];

pub fn sha256(data: &[u8]) -> Sha256Digest {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}
