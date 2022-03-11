use cncs_sm2_kit::types::PrivateKey;

fn main() {
    let private_key = PrivateKey::random_via_libsm();
    let public_key = private_key.public_key();

    println!("private_key: {}", private_key.to_hex_str());
    println!("public_key: {}", public_key.to_concated_hex_str());
}
