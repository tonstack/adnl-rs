use aes::cipher::KeyIvInit;
use ciborium_io::Write;
use ctr::cipher::StreamCipher;
use sha2::{Digest, Sha256};

use crate::primitives::AdnlAes;
use crate::{AdnlAesParams, AdnlError, Empty};

/// Low-level outgoing datagram generator
pub struct AdnlSender {
    aes: AdnlAes,
}

impl AdnlSender {
    /// Create sender with given session parameters
    pub fn new(aes_params: &AdnlAesParams) -> Self {
        Self {
            aes: AdnlAes::new(aes_params.tx_key().into(), aes_params.tx_nonce().into()),
        }
    }

    /// Get estimated size of datagram for the given buffer
    pub fn estimate_packet_length(buffer: &[u8]) -> u32 {
        buffer.len() as u32 + 68
    }

    /// Send `buffer` over `transport` with `nonce`. Note that `nonce` must be random
    /// in order to prevent bit-flipping attacks when an attacker knows whole plaintext in datagram.
    pub fn send<W: Write>(
        &mut self,
        transport: &mut W,
        nonce: &mut [u8; 32],
        buffer: &mut [u8],
    ) -> Result<(), AdnlError<Empty, W, Empty>> {
        // remember not to send more than 4 GiB in a single packet
        let mut length = ((buffer.len() + 64) as u32).to_le_bytes();

        // calc hash
        let mut hasher = Sha256::new();
        hasher.update(*nonce);
        hasher.update(&*buffer);
        let mut hash: [u8; 32] = hasher.finalize().try_into().unwrap();

        // encrypt packet
        self.aes.apply_keystream(&mut length);
        self.aes.apply_keystream(nonce);
        self.aes.apply_keystream(buffer);
        self.aes.apply_keystream(&mut hash);

        // write to transport
        transport
            .write_all(&length)
            .map_err(|e| AdnlError::WriteError(e))?;
        transport
            .write_all(nonce)
            .map_err(|e| AdnlError::WriteError(e))?;
        transport
            .write_all(buffer)
            .map_err(|e| AdnlError::WriteError(e))?;
        transport
            .write_all(&hash)
            .map_err(|e| AdnlError::WriteError(e))?;
        transport.flush().map_err(|e| AdnlError::WriteError(e))?;

        Ok(())
    }
}
