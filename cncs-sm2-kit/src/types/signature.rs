use core::fmt;

use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num as _;

#[derive(Clone)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
}
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &self.r.to_str_radix(16).to_uppercase())
            .field("s", &self.s.to_str_radix(16).to_uppercase())
            .finish()
    }
}
impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_concated_hex_str())
    }
}

impl Signature {
    pub fn new(r: BigUint, s: BigUint) -> Self {
        Self { r, s }
    }

    pub fn from_bytes(r_bytes: &[u8], s_bytes: &[u8]) -> Self {
        let r = BigUint::from_bytes_be(r_bytes);
        let s = BigUint::from_bytes_be(s_bytes);
        Self { r, s }
    }

    pub fn from_hex_str(r_hex_str: &str, s_hex_str: &str) -> Result<Self, ParseBigIntError> {
        let r = BigUint::from_str_radix(r_hex_str, 16)?;
        let s = BigUint::from_str_radix(s_hex_str, 16)?;
        Ok(Self { r, s })
    }

    pub fn from_concated_hex_str(hex_str: &str) -> Result<Self, SignatureFromConcatedHexStrError> {
        match hex_str.len() {
            128 => Self::from_hex_str(&hex_str[..64], &hex_str[64..])
                .map_err(SignatureFromConcatedHexStrError::ParseBigIntError),
            _ => Err(SignatureFromConcatedHexStrError::Invalid),
        }
    }

    pub fn to_concated_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend(super::to_bytes::<32>(&self.r));
        bytes.extend(super::to_bytes::<32>(&self.s));
        bytes
    }

    pub fn to_concated_hex_str(&self) -> String {
        super::to_hex_str(&self.to_concated_bytes())
    }
}

#[derive(Debug)]
pub enum SignatureFromConcatedHexStrError {
    Invalid,
    ParseBigIntError(ParseBigIntError),
}
impl fmt::Display for SignatureFromConcatedHexStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SignatureFromConcatedHexStrError {}

//
//
//
impl From<&Signature> for libsm::sm2::signature::Signature {
    fn from(s: &Signature) -> Self {
        Self::new(s.r.to_bytes_be().as_ref(), s.s.to_bytes_be().as_ref())
    }
}

impl From<&libsm::sm2::signature::Signature> for Signature {
    fn from(s: &libsm::sm2::signature::Signature) -> Self {
        Self::new(s.get_r().to_owned(), s.get_s().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{PrivateKey, PUBLIC_KEY_X, PUBLIC_KEY_Y};

    #[test]
    fn test_to_concated_hex_str() {
        let signature = Signature::from_hex_str(PUBLIC_KEY_X, PUBLIC_KEY_Y).unwrap();
        println!("{:?}", signature);
        println!("{}", signature);
        assert_eq!(
            signature.to_concated_hex_str(),
            format!("{}{}", PUBLIC_KEY_X, PUBLIC_KEY_Y)
        );

        let sk = "EE198D2262508EDC3A96DA1C1BE646EAF24911B31A0749AC5E6BC31EF501A052";
        let id = "ID12341234567890";
        let data = [
            22, 7, 7, 12, 15, 38, 0, 214, 2, 22, 7, 7, 12, 15, 38, 0, 0, 0, 125, 125, 0, 0, 0, 0,
            15, 160, 15, 160, 0, 0, 0, 34, 32, 34, 32, 0, 0, 40, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 22, 7, 7, 12, 15, 38, 0, 0, 0, 0, 0, 0, 84, 69, 83, 84, 49, 50, 51, 49, 50,
            51, 52, 53, 54, 55, 56, 57, 48, 83, 67, 73, 78, 49, 50, 51, 52, 49, 50, 51, 52, 53, 54,
            55, 56, 57, 48, 67, 86, 78, 49, 50, 51, 52, 53, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
            73, 85, 80, 82, 49, 50, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54,
            55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0,
            0, 0, 3, 0, 0, 0, 4,
        ];
        let err_signature =  "29AA22C223E560C5C39870FC62ADB0C163BB26CF2D4DDA6B43C1C0C7E603E9715372B0F8E0257C1EFCF90C71C11FB7CE86EA271D76B6C70E02B6471446151C";
        let sk = PrivateKey::from_hex_str(sk).unwrap();
        let signature = crate::sign(&sk, data, Some(id));
        assert_ne!(signature.to_concated_hex_str(), err_signature);
        assert_eq!(signature.to_concated_bytes().len(), 64);
    }
}
