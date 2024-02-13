use crate::primitives::AdnlAes;
use crate::{AdnlAesParams, AdnlError};
use aes::cipher::KeyIvInit;
use ctr::cipher::StreamCipher;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Low-level incoming datagram processor
pub struct AdnlReceiver {
    aes: AdnlAes,
}

impl AdnlReceiver {
    /// Create receiver with given session parameters
    pub fn new(aes_params: &AdnlAesParams) -> Self {
        Self {
            aes: AdnlAes::new(aes_params.rx_key().into(), aes_params.rx_nonce().into()),
        }
    }

    /// Receive datagram from `transport`. Received parts of the decrypted buffer
    /// will be sent to `consumer`, which usually can be just `Vec`. Note that
    /// data can be processed before this function will return, but in case of
    /// [`AdnlError::IntegrityError`] you must assume that the data was tampered.
    ///
    /// You can adjust `BUFFER` according to your memory requirements.
    /// Recommended size is 8192 bytes.
    pub async fn receive<R: AsyncReadExt + Unpin, C: AsyncWriteExt + Unpin, const BUFFER: usize>(
        &mut self,
        transport: &mut R,
        consumer: &mut C,
    ) -> Result<(), AdnlError> {
        // read length
        let mut length = [0u8; 4];
        log::debug!("reading length");
        transport
            .read_exact(&mut length).await
            .map_err(AdnlError::ReadError)?;
        self.aes.apply_keystream(&mut length);
        let length = u32::from_le_bytes(length);
        log::debug!("length = {}", length);
        if length < 64 {
            return Err(AdnlError::TooShortPacket);
        }

        let mut hasher = Sha256::new();

        // read nonce
        let mut nonce = [0u8; 32];
        log::debug!("reading nonce");
        transport
            .read_exact(&mut nonce).await
            .map_err(AdnlError::ReadError)?;
        self.aes.apply_keystream(&mut nonce);
        hasher.update(nonce);

        // read buffer chunks, decrypt and write to consumer
        if BUFFER > 0 {
            let mut buffer = [0u8; BUFFER];
            let mut bytes_to_read = length as usize - 64;
            while bytes_to_read >= BUFFER {
                log::debug!(
                    "chunked read (chunk len = {}), {} bytes remaining",
                    BUFFER,
                    bytes_to_read
                );
                transport
                    .read_exact(&mut buffer).await
                    .map_err(AdnlError::ReadError)?;
                self.aes.apply_keystream(&mut buffer);
                hasher.update(buffer);
                consumer
                    .write_all(&buffer).await
                    .map_err(AdnlError::WriteError)?;
                bytes_to_read -= BUFFER;
            }

            // read last chunk
            if bytes_to_read > 0 {
                log::debug!("last chunk, {} bytes remaining", bytes_to_read);
                let buffer = &mut buffer[..bytes_to_read];
                transport
                    .read_exact(buffer).await
                    .map_err(AdnlError::ReadError)?;
                self.aes.apply_keystream(buffer);
                hasher.update(&buffer);
                consumer
                    .write_all(buffer).await
                    .map_err(AdnlError::WriteError)?;
            }
        }

        let mut given_hash = [0u8; 32];
        log::debug!("reading hash");
        transport
            .read_exact(&mut given_hash).await
            .map_err(AdnlError::ReadError)?;
        self.aes.apply_keystream(&mut given_hash);

        let real_hash = hasher.finalize();
        if real_hash.as_slice() != given_hash {
            return Err(AdnlError::IntegrityError);
        }

        log::debug!("receive finished successfully");

        Ok(())
    }
}
