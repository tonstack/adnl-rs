use ctr::cipher::StreamCipher;
use aes::cipher::KeyIvInit;
use sha2::{Sha256, Digest};
use crate::{AdnlAddress, AdnlAesParams, AdnlPublicKey, AdnlSecret, AdnlClient, Empty, AdnlError};
use ciborium_io::{Write, Read};
use crate::primitives::AdnlAes;


pub struct AdnlHandshake<P: AdnlPublicKey> {
    receiver: AdnlAddress,
    sender: P,
    aes_params: AdnlAesParams,
    secret: AdnlSecret,
}

impl<P: AdnlPublicKey> AdnlHandshake<P> {
    pub fn new(receiver: AdnlAddress, sender: P, secret: AdnlSecret, aes_params: AdnlAesParams) -> Self {
        Self {
            receiver,
            sender,
            aes_params,
            secret,
        }
    }

    pub fn aes_params(&self) -> &AdnlAesParams {
        &self.aes_params
    }

    pub fn to_bytes(&self) -> [u8; 256] {
        let mut packet = [0u8; 256];
        packet[..32].copy_from_slice(self.receiver.as_bytes());
        packet[32..64].copy_from_slice(&self.sender.to_bytes());

        let mut raw_params = self.aes_params.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&raw_params);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&self.secret.as_bytes()[..16]);
        key[16..32].copy_from_slice(&hash[16..32]);
        let mut nonce = [0u8; 16];
        nonce[..4].copy_from_slice(&hash[..4]);
        nonce[4..16].copy_from_slice(&self.secret.as_bytes()[20..32]);

        let mut aes = AdnlAes::new(key.as_slice().into(), nonce.as_slice().into());
        aes.apply_keystream(&mut raw_params);

        packet[64..96].copy_from_slice(&hash);
        packet[96..256].copy_from_slice(&raw_params);
        packet
    }

    pub fn perform_handshake<T: Read + Write>(&self, transport: T) -> Result<AdnlClient<T>, AdnlError<T, T, Empty>> {
        AdnlClient::perform_handshake(transport, self)
    }
}