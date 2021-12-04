#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EncryptMode {
    C1C2C3,
    C1C3C2,
}
impl Default for EncryptMode {
    fn default() -> Self {
        Self::C1C3C2
    }
}

impl EncryptMode {
    pub fn to_gmsm_mode(&self) -> usize {
        match self {
            EncryptMode::C1C2C3 => gmsm::g2::consts::C1C2C3,
            EncryptMode::C1C3C2 => gmsm::g2::consts::C1C3C2,
        }
    }
}
