use sha2::{Sha256, Digest};

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let sha = Sha256::digest(data);
    let sha = Sha256::digest(&sha[..]);
    let mut arr = [0; 32];
    arr.copy_from_slice(&sha[..]);
    arr
}
