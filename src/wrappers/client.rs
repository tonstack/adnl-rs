use ciborium_io::{Read, Write};
use crate::{AdnlHandshake, AdnlReceiver, AdnlSender, AdnlError, Empty, AdnlPublicKey};

pub struct AdnlClient<T: Read + Write> {
    sender: AdnlSender,
    receiver: AdnlReceiver,
    transport: T,
}

impl<T: Read + Write> AdnlClient<T> {
    pub fn perform_handshake<P: AdnlPublicKey>(mut transport: T, handshake: &AdnlHandshake<P>) -> Result<Self, AdnlError<T, T, Empty>> {
        // send handshake
        transport.write_all(&handshake.to_bytes()).map_err(|e| AdnlError::WriteError(e))?;

        // receive empty message to ensure that server knows our AES keys
        let mut client = Self {
            sender: AdnlSender::new(handshake.aes_params()),
            receiver: AdnlReceiver::new(handshake.aes_params()),
            transport,
        };
        client.receive::<_, 0>(&mut Empty).map_err(|e| match e {
            AdnlError::ReadError(err) => AdnlError::ReadError(err),
            AdnlError::WriteError(_) => unreachable!(),
            AdnlError::ConsumeError(err) => AdnlError::ConsumeError(err),
            AdnlError::IntegrityError => AdnlError::IntegrityError,
            AdnlError::TooShortPacket => AdnlError::TooShortPacket
        })?;
        Ok(client)
    }

    pub fn send(&mut self, data: &mut [u8], nonce: &mut [u8; 32]) -> Result<(), AdnlError<Empty, T, Empty>> {
        self.sender.send(&mut self.transport, nonce, data)
    }

    pub fn receive<C: Write, const BUFFER: usize>(&mut self, consumer: &mut C) -> Result<(), AdnlError<T, Empty, C>> {
        self.receiver.receive::<_, _, BUFFER>(&mut self.transport, consumer)
    }
}