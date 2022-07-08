pub mod encrypt_mode;
pub mod private_key;
pub mod public_key;
pub mod signature;

pub use encrypt_mode::EncryptMode;
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;

pub(crate) fn to_bytes<const LEN: usize>(num: &num_bigint::BigUint) -> [u8; LEN] {
    let data = num.to_bytes_be();
    let mut ret = [0; LEN];
    ret[LEN - data.len()..].copy_from_slice(&data);
    ret
}

#[inline]
pub(crate) fn to_hex_str(data: &[u8]) -> String {
    hex_simd::encode_to_boxed_str(data, hex_simd::AsciiCase::Upper).into()
}
