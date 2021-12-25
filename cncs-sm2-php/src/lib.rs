use cncs_sm2_kit::{
    decrypt, encrypt, sign,
    types::{EncryptMode, PrivateKey, PublicKey, Signature},
    verify,
};
use ext_php_rs::prelude::{php_function, php_module, ModuleBuilder, PhpResult};

#[php_function]
pub fn sm2_sign(private_key_hex: &str, msg: &str, user_id: Option<&str>) -> PhpResult<String> {
    let private_key = PrivateKey::from_hex_str(private_key_hex)
        .map_err(|err| format!("Parse private_key_hex failed, err: {}", err))?;

    let signature = sign(&private_key, msg, user_id);

    Ok(signature.to_concated_hex_str())
}

#[php_function]
pub fn sm2_verify(
    public_key_hex: &str,
    msg: &str,
    user_id: Option<&str>,
    signature_hex: &str,
) -> PhpResult<bool> {
    let public_key = PublicKey::from_concated_hex_str(public_key_hex)
        .map_err(|err| format!("Parse public_key_hex failed, err: {}", err))?;

    let signature = Signature::from_concated_hex_str(signature_hex)
        .map_err(|err| format!("Parse signature_hex failed, err: {}", err))?;

    let ret = verify(&public_key, msg, user_id, &signature)
        .map_err(|err| format!("Verify failed, err: {}", err))?;

    Ok(ret)
}

#[php_function]
pub fn sm2_encrypt(public_key_hex: &str, msg: &str, mode: Option<u8>) -> PhpResult<String> {
    let public_key = PublicKey::from_concated_hex_str(public_key_hex)
        .map_err(|err| format!("Parse public_key_hex failed, err: {}", err))?;

    let mode = if let Some(mode) = mode {
        Some(prase_encrypt_mode(mode)?)
    } else {
        None
    };

    let msg_encrypted = encrypt(&public_key, msg, mode);
    let msg_encrypted_base64 = base64::encode(&msg_encrypted);

    Ok(msg_encrypted_base64)
}

#[php_function]
pub fn sm2_decrypt(
    private_key_hex: &str,
    msg_encrypted_base64: &str,
    mode: Option<u8>,
) -> PhpResult<String> {
    let private_key = PrivateKey::from_hex_str(private_key_hex)
        .map_err(|err| format!("Parse private_key_hex failed, err: {}", err))?;

    let mode = if let Some(mode) = mode {
        Some(prase_encrypt_mode(mode)?)
    } else {
        None
    };

    let msg_encrypted = base64::decode(msg_encrypted_base64)
        .map_err(|err| format!("Parse msg_encrypted_base64 failed, err: {}", err))?;

    let msg = decrypt(&private_key, msg_encrypted, mode);

    let msg_string = String::from_utf8(msg)
        .map_err(|err| format!("Convert msg to string failed, err: {}", err))?;

    Ok(msg_string)
}

fn prase_encrypt_mode(mode: u8) -> Result<EncryptMode, String> {
    match mode {
        0 => Ok(EncryptMode::C1C3C2),
        1 => Ok(EncryptMode::C1C2C3),
        _ => Err("Invalid mode".into()),
    }
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
