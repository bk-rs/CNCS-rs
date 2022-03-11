pub use gmsm;
pub use libsm;

use core::fmt;

use gmsm::g2::subject::{
    decrypt as gmsm_decrypt, encrypt as gmsm_encrypt, PrivateKey as GmsmPrivateKey,
    PublicKey as GmsmPublicKey,
};
use libsm::sm2::{
    ecc::Point as LibsmPoint,
    signature::{SigCtx as LibsmSigCtx, Signature as LibsmSignature},
};

pub mod types;

use self::types::{EncryptMode, PrivateKey, PublicKey, Signature};

//
//
//
pub fn sign<'a>(
    private_key: &PrivateKey,
    msg: impl AsRef<[u8]>,
    user_id: impl Into<Option<&'a str>>,
) -> Signature {
    let msg = msg.as_ref();
    let user_id = user_id.into();

    let sk = &private_key.d;

    let pk = LibsmPoint::from(private_key);

    let sig_ctx = LibsmSigCtx::new();
    let signature = if let Some(user_id) = user_id {
        let e_bytes = sig_ctx.hash(user_id, &pk, msg);
        sig_ctx.sign_raw(&e_bytes[..], sk)
    } else {
        sig_ctx.sign(msg, sk, &pk)
    };

    Signature::from(&signature)
}

//
//
//
pub fn verify<'a>(
    public_key: &PublicKey,
    msg: impl AsRef<[u8]>,
    user_id: impl Into<Option<&'a str>>,
    signature: &Signature,
) -> Result<bool, VerifyError> {
    let msg = msg.as_ref();
    let user_id = user_id.into();

    let pk = LibsmPoint::try_from(public_key).map_err(VerifyError::ToLibsmPointFailed)?;

    let signature = LibsmSignature::from(signature);

    let sig_ctx = LibsmSigCtx::new();
    let ret = if let Some(user_id) = user_id {
        let e_bytes = sig_ctx.hash(user_id, &pk, msg);
        sig_ctx.verify_raw(&e_bytes[..], &pk, &signature)
    } else {
        sig_ctx.verify(msg, &pk, &signature)
    };

    Ok(ret)
}
#[derive(Debug)]
pub enum VerifyError {
    ToLibsmPointFailed(String),
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for VerifyError {}

//
//
//
pub fn encrypt(
    public_key: &PublicKey,
    msg: impl AsRef<[u8]>,
    mode: impl Into<Option<EncryptMode>>,
) -> Vec<u8> {
    let msg = msg.as_ref();
    let mode: EncryptMode = mode.into().unwrap_or_default();

    gmsm_encrypt(
        GmsmPublicKey::from(public_key),
        msg.to_vec(),
        mode.to_gmsm_mode(),
    )
}

//
//
//
pub fn decrypt(
    private_key: &PrivateKey,
    msg: impl AsRef<[u8]>,
    mode: impl Into<Option<EncryptMode>>,
) -> Vec<u8> {
    let msg = msg.as_ref();
    let mode: EncryptMode = mode.into().unwrap_or_default();

    gmsm_decrypt(
        GmsmPrivateKey::from(private_key),
        msg.to_vec(),
        mode.to_gmsm_mode(),
    )
}

#[cfg(test)]
pub(crate) const PRIVATE_KEY: &str =
    "7D2B2391F9633469156F700F8B00D9C85EB6B5327B68684483742EC4AC43043D";
#[cfg(test)]
pub(crate) const PUBLIC_KEY_X: &str =
    "FE1FC819D6A8827DB65BF1E114713CE68F116DAA3D6A75A3D8A5E48FAD68C591";
#[cfg(test)]
pub(crate) const PUBLIC_KEY_Y: &str =
    "7F925FA394747EC86613C62EF4FD77E97BD8FF9744453CD4728CFE37F955183A";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let private_key = PrivateKey::from_hex_str(PRIVATE_KEY).unwrap();

        let public_key = PublicKey::from_hex_str(PUBLIC_KEY_X, PUBLIC_KEY_Y).unwrap();

        let msg = "TEST";
        let signature = sign(&private_key, msg, None);
        let ret = verify(&public_key, msg, None, &signature).unwrap();
        assert!(ret);
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let private_key = PrivateKey::from_hex_str(PRIVATE_KEY).unwrap();

        let public_key = PublicKey::from_hex_str(PUBLIC_KEY_X, PUBLIC_KEY_Y).unwrap();

        let msg = "TEST";
        let encrypt_bytes = encrypt(&public_key, msg, None);
        let decrypt_bytes = decrypt(&private_key, encrypt_bytes, None);
        assert_eq!(String::from_utf8(decrypt_bytes).unwrap(), msg);
    }
}
