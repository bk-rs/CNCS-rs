use std::fmt;

use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num as _;

use crate::types::PublicKey;

#[derive(Clone)]
pub struct PrivateKey {
    pub d: BigUint,
}
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKey(d: {})",
            &self.d.to_str_radix(16).to_uppercase()
        )
    }
}

impl PrivateKey {
    pub fn new(d: BigUint) -> Self {
        Self { d }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let d = BigUint::from_bytes_be(bytes);
        Self { d }
    }

    pub fn from_hex_str(hex_str: &str) -> Result<Self, ParseBigIntError> {
        let d = BigUint::from_str_radix(hex_str, 16)?;
        Ok(Self { d })
    }

    pub fn random_via_libsm() -> Self {
        let curve = libsm::sm2::ecc::EccCtx::new();

        let d = curve.random_uint();

        Self { d }
    }

    pub fn random_via_gmsm() -> Self {
        let d = gmsm::g2::subject::generate_key().d;

        Self { d }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&gmsm::g2::subject::PrivateKey::from(self).public_key)
    }
}

//
//
//
impl From<&PrivateKey> for gmsm::g2::subject::PrivateKey {
    fn from(k: &PrivateKey) -> Self {
        let sm2_p256_curve = gmsm::g2::p256::Sm2P256Curve::new();
        let (pkx, pky) = sm2_p256_curve.scalar_base_mult(k.d.to_bytes_be());

        Self {
            curve: sm2_p256_curve.params(),
            public_key: gmsm::g2::subject::PublicKey { x: pkx, y: pky },
            d: k.d.to_owned(),
        }
    }
}

impl From<&PrivateKey> for libsm::sm2::ecc::Point {
    fn from(k: &PrivateKey) -> Self {
        let curve = libsm::sm2::ecc::EccCtx::new();

        curve.g_mul(&k.d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{PRIVATE_KEY, PUBLIC_KEY_X, PUBLIC_KEY_Y};

    #[test]
    fn test_get_point_for_sign() {
        let private_key = PrivateKey::from_hex_str(PRIVATE_KEY).unwrap();
        for _ in 1..=3 {
            let libsm::sm2::ecc::Point { x, y, z } = libsm::sm2::ecc::Point::from(&private_key);
            println!(
                "{} {} {}",
                x.to_biguint().to_str_radix(16).to_uppercase(),
                y.to_biguint().to_str_radix(16).to_uppercase(),
                z.to_biguint().to_str_radix(16).to_uppercase()
            );
            assert_eq!(
                x.to_biguint(),
                BigUint::from_str_radix(
                    "F3FC0536A1105A7961BE0C998E7639A1F0D8E4F5070382839966C300C603091A",
                    16
                )
                .unwrap()
            );
            assert_eq!(
                y.to_biguint(),
                BigUint::from_str_radix(
                    "94652C003EC5974F80771CE9C8E6FA781E4DCAB95D8BDF0968DA539EF6CBA69D",
                    16
                )
                .unwrap()
            );
            assert_eq!(
                z.to_biguint(),
                BigUint::from_str_radix(
                    "A88F4AEA9F6E77ED205AE639756B6ADF312425A9C2FB1B8E506697810DDEEE71",
                    16
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn test_public_key() {
        let private_key = PrivateKey::from_hex_str(PRIVATE_KEY).unwrap();
        for _ in 1..=3 {
            let public_key = private_key.public_key();
            println!("{}", public_key);
            assert_eq!(
                public_key.x,
                BigUint::from_str_radix(PUBLIC_KEY_X, 16).unwrap()
            );
            assert_eq!(
                public_key.y,
                BigUint::from_str_radix(PUBLIC_KEY_Y, 16).unwrap()
            );
        }
    }

    #[test]
    fn test_convert_for_libsm() {
        let libsm_sig_ctx = libsm::sm2::signature::SigCtx::new();
        let (libsm_point, libsm_private_key) = libsm_sig_ctx.new_keypair();

        let private_key = PrivateKey::new(libsm_private_key);

        let libsm::sm2::ecc::Point { x, y, z } = libsm::sm2::ecc::Point::from(&private_key);

        assert_eq!(libsm_point.x.to_biguint(), x.to_biguint());
        assert_eq!(libsm_point.y.to_biguint(), y.to_biguint());
        assert_eq!(libsm_point.z.to_biguint(), z.to_biguint());
    }

    #[test]
    fn test_convert_for_gmsm() {
        let gmsm_private_key = gmsm::g2::subject::generate_key();

        let private_key = PrivateKey::new(gmsm_private_key.d.to_owned());

        let public_key = private_key.public_key();

        assert_eq!(public_key.x, gmsm_private_key.public_key.x);
        assert_eq!(public_key.y, gmsm_private_key.public_key.y);
    }
}
