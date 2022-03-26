use sha2::{Sha256, Digest};
use ciborium_io::{Read, Write};

pub trait CryptoRandom: rand_core::RngCore + rand_core::CryptoRng {}

impl<T> CryptoRandom for T where T: rand_core::RngCore + rand_core::CryptoRng {}

pub trait AdnlPublicKey {
    fn address(&self) -> AdnlAddress {
        let mut hasher = Sha256::new();
        hasher.update([0xc6, 0xb4, 0x13, 0x48]);  // type id - always ed25519
        hasher.update(&self.to_bytes());
        AdnlAddress(hasher.finalize().try_into().unwrap())
    }

    fn to_bytes(&self) -> [u8; 32];
}

impl AdnlPublicKey for [u8; 32] {
    fn to_bytes(&self) -> [u8; 32] {
        *self
    }
}

pub trait AdnlPrivateKey {
    type PublicKey: AdnlPublicKey;

    fn key_agreement<P: AdnlPublicKey>(&self, their_public: P) -> AdnlSecret;
    fn public(&self) -> Self::PublicKey;
}

pub struct AdnlSecret([u8; 32]);

pub struct AdnlAddress([u8; 32]);

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

    pub fn to_bytes(&self) -> [u8; 160] {
        let mut result = [0u8; 160];
        result[..32].copy_from_slice(&self.rx_key);
        result[32..64].copy_from_slice(&self.tx_key);
        result[64..80].copy_from_slice(&self.rx_nonce);
        result[80..96].copy_from_slice(&self.tx_nonce);
        result[96..160].copy_from_slice(&self.padding);
        result
    }

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

#[derive(Debug)]
pub struct Empty;

impl Write for Empty {
    type Error = ();

    fn write_all(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Read for Empty {
    type Error = ();

    fn read_exact(&mut self, _data: &mut [u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum AdnlError<R: Read, W: Write, C: Write> {
    ReadError(R::Error),
    WriteError(W::Error),
    ConsumeError(C::Error),
    IntegrityError,
    TooShortPacket,
}