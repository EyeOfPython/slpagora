use sha2::{Sha256, Digest};
use ripemd160::Ripemd160;

pub fn single_sha256(data: &[u8]) -> [u8; 32] {
    let sha = Sha256::digest(data);
    let mut arr = [0; 32];
    arr.copy_from_slice(&sha[..]);
    arr
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let sha = Sha256::digest(data);
    let sha = Sha256::digest(&sha[..]);
    let mut arr = [0; 32];
    arr.copy_from_slice(&sha[..]);
    arr
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut arr = [0; 20];
    arr.copy_from_slice(&Ripemd160::digest(&Sha256::digest(data)));
    arr
}
