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
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.r.to_bytes_be()[..]);
        bytes.extend_from_slice(&self.s.to_bytes_be()[..]);
        bytes
    }

    pub fn to_concated_hex_str(&self) -> String {
        format!(
            "{}{}",
            &self.r.to_str_radix(16).to_uppercase(),
            &self.s.to_str_radix(16).to_uppercase()
        )
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

    use crate::{PUBLIC_KEY_X, PUBLIC_KEY_Y};

    #[test]
    fn test_to_concated_hex_str() {
        let signature = Signature::from_hex_str(PUBLIC_KEY_X, PUBLIC_KEY_Y).unwrap();
        println!("{:?}", signature);
        println!("{}", signature);
        assert_eq!(
            signature.to_concated_hex_str(),
            format!("{}{}", PUBLIC_KEY_X, PUBLIC_KEY_Y)
        )
    }
}
