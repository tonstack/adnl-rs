use std::io::Error;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub trait CryptoRandom: rand_core::RngCore + rand_core::CryptoRng {}

impl<T> CryptoRandom for T where T: rand_core::RngCore + rand_core::CryptoRng {}

pub trait AdnlPublicKey {
    fn address(&self) -> AdnlAddress {
        let mut hasher = Sha256::new();
        hasher.update([0xc6, 0xb4, 0x13, 0x48]); // type id - always ed25519
        hasher.update(self.to_bytes());
        AdnlAddress(hasher.finalize().try_into().unwrap())
    }

    fn to_bytes(&self) -> [u8; 32];
}

/// Public key can be provided using raw slice
impl AdnlPublicKey for [u8; 32] {
    fn to_bytes(&self) -> [u8; 32] {
        *self
    }
}

/// Trait which must be implemented to perform key agreement inside [`AdnlHandshake`]
pub trait AdnlPrivateKey {
    type PublicKey: AdnlPublicKey;

    /// Perform key agreement protocol (usually x25519) between our private key
    /// and their public
    fn key_agreement<P: AdnlPublicKey>(&self, their_public: P) -> AdnlSecret;

    /// Get public key corresponding to this private
    fn public(&self) -> Self::PublicKey;
}

/// Wrapper struct to hold the secret, result of ECDH between peers
pub struct AdnlSecret([u8; 32]);

/// Wrapper struct to hold ADNL address, which is a hash of public key
pub struct AdnlAddress([u8; 32]);

/// Session parameters for AES-CTR encryption of datagrams
pub struct AdnlAesParams {
    rx_key: [u8; 32],
    tx_key: [u8; 32],
    rx_nonce: [u8; 16],
    tx_nonce: [u8; 16],
    padding: [u8; 64],
}

impl From<[u8; 160]> for AdnlAesParams {
    fn from(raw_buffer: [u8; 160]) -> Self {
        Self {
            rx_key: raw_buffer[..32].try_into().unwrap(),
            tx_key: raw_buffer[32..64].try_into().unwrap(),
            rx_nonce: raw_buffer[64..80].try_into().unwrap(),
            tx_nonce: raw_buffer[80..96].try_into().unwrap(),
            padding: raw_buffer[96..160].try_into().unwrap(),
        }
    }
}

impl AdnlAesParams {
    pub fn rx_key(&self) -> &[u8; 32] {
        &self.rx_key
    }

    pub fn tx_key(&self) -> &[u8; 32] {
        &self.tx_key
    }

    pub fn rx_nonce(&self) -> &[u8; 16] {
        &self.rx_nonce
    }

    pub fn tx_nonce(&self) -> &[u8; 16] {
        &self.tx_nonce
    }

    /// Serialize this structure into bytes to use in handshake packet
    pub fn to_bytes(&self) -> [u8; 160] {
        let mut result = [0u8; 160];
        result[..32].copy_from_slice(&self.rx_key);
        result[32..64].copy_from_slice(&self.tx_key);
        result[64..80].copy_from_slice(&self.rx_nonce);
        result[80..96].copy_from_slice(&self.tx_nonce);
        result[96..160].copy_from_slice(&self.padding);
        result
    }

    /// Generate random session parameters
    pub fn random<T: CryptoRandom>(csprng: &mut T) -> Self {
        let mut result: AdnlAesParams = Default::default();
        csprng.fill_bytes(&mut result.rx_key);
        csprng.fill_bytes(&mut result.tx_key);
        csprng.fill_bytes(&mut result.rx_nonce);
        csprng.fill_bytes(&mut result.tx_nonce);
        csprng.fill_bytes(&mut result.padding);
        result
    }
}

impl Default for AdnlAesParams {
    fn default() -> Self {
        Self {
            rx_key: [0; 32],
            tx_key: [0; 32],
            rx_nonce: [0; 16],
            tx_nonce: [0; 16],
            padding: [0; 64],
        }
    }
}

impl From<[u8; 32]> for AdnlSecret {
    fn from(secret: [u8; 32]) -> Self {
        Self(secret)
    }
}

impl AdnlAddress {
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AdnlSecret {
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Common error type
#[derive(Debug, Error)]
pub enum AdnlError {
    #[error("Read error")]
    ReadError(Error),
    #[error("Write error")]
    WriteError(Error),
    #[error("Consume error")]
    ConsumeError(Error),
    #[error("Integrity error")]
    IntegrityError,
    #[error("TooShortPacket error")]
    TooShortPacket,
    #[error(transparent)]
    OtherError(#[from] Error)
}
