use ctr::cipher::StreamCipher;
use sha2::{Sha256, Digest};
use aes::cipher::KeyIvInit;
use ciborium_io::{Read, Write};
use crate::{AdnlAesParams, Empty, AdnlError};
use crate::primitives::AdnlAes;

pub struct AdnlReceiver {
    aes: AdnlAes,
}

impl AdnlReceiver {
    pub fn new(aes_params: &AdnlAesParams) -> Self {
        Self {
            aes: AdnlAes::new(aes_params.rx_key().into(), aes_params.rx_nonce().into())
        }
    }

    pub fn receive<R: Read, C: Write, const BUFFER: usize>(&mut self, transport: &mut R, consumer: &mut C) -> Result<(), AdnlError<R, Empty, C>> {
        // read length
        let mut length = [0u8; 4];
        log::debug!("reading length");
        transport.read_exact(&mut length).map_err(|e| AdnlError::ReadError(e))?;
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
        transport.read_exact(&mut nonce).map_err(|e| AdnlError::ReadError(e))?;
        self.aes.apply_keystream(&mut nonce);
        hasher.update(&nonce);

        // read buffer chunks, decrypt and write to consumer
        if BUFFER > 0 {
            let mut buffer = [0u8; BUFFER];
            let mut bytes_to_read = length as usize - 64;
            while bytes_to_read >= BUFFER {
                log::debug!("chunked read (chunk len = {}), {} bytes remaining", BUFFER, bytes_to_read);
                transport.read_exact(&mut buffer).map_err(|e| AdnlError::ReadError(e))?;
                self.aes.apply_keystream(&mut buffer);
                hasher.update(&buffer);
                consumer.write_all(&buffer).map_err(|e| AdnlError::ConsumeError(e))?;
                bytes_to_read -= BUFFER;
            }

            // read last chunk
            if bytes_to_read > 0 {
                log::debug!("last chunk, {} bytes remaining", bytes_to_read);
                let buffer = &mut buffer[..bytes_to_read];
                transport.read_exact(buffer).map_err(|e| AdnlError::ReadError(e))?;
                self.aes.apply_keystream(buffer);
                hasher.update(&buffer);
                consumer.write_all(buffer).map_err(|e| AdnlError::ConsumeError(e))?;
            }
        }

        let mut given_hash = [0u8; 32];
        log::debug!("reading hash");
        transport.read_exact(&mut given_hash).map_err(|e| AdnlError::ReadError(e))?;
        self.aes.apply_keystream(&mut given_hash);

        let real_hash = hasher.finalize();
        if real_hash.as_slice() != &given_hash {
            return Err(AdnlError::IntegrityError);
        }

        log::debug!("receive finished successfully");

        Ok(())
    }
}