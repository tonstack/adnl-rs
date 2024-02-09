use crate::{AdnlError, AdnlHandshake, AdnlPublicKey, AdnlReceiver, AdnlSender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Abstraction over [`AdnlSender`] and [`AdnlReceiver`] to keep things simple
pub struct AdnlClient<T: AsyncReadExt + AsyncWriteExt> {
    sender: AdnlSender,
    receiver: AdnlReceiver,
    transport: T,
}

impl<T: AsyncReadExt + AsyncWriteExt + Unpin> AdnlClient<T> {
    /// Send `handshake` over `transport` and check that handshake was successful
    pub async fn perform_handshake<P: AdnlPublicKey>(
        mut transport: T,
        handshake: &AdnlHandshake<P>,
    ) -> Result<Self, AdnlError> {
        // send handshake
        transport
            .write_all(&handshake.to_bytes()).await
            .map_err(AdnlError::WriteError)?;

        // receive empty message to ensure that server knows our AES keys
        let mut client = Self {
            sender: AdnlSender::new(handshake.aes_params()),
            receiver: AdnlReceiver::new(handshake.aes_params()),
            transport,
        };
        client.receive::<_, 0>(&mut Empty).await?;
        Ok(client)
    }

    /// Send `data` to another peer. Random `nonce` must be provided to eliminate bit-flipping attacks.
    pub async fn send(
        &mut self,
        data: &mut [u8],
        nonce: &mut [u8; 32],
    ) -> Result<(), AdnlError> {
        self.sender.send(&mut self.transport, nonce, data).await
    }

    /// Receive data from another peer into `consumer` which will process the data. Set `BUFFER`
    /// according to your memory requirements, recommended size is 8192 bytes.
    pub async fn receive<C: AsyncWriteExt + Unpin, const BUFFER: usize>(
        &mut self,
        consumer: &mut C,
    ) -> Result<(), AdnlError> {
        self.receiver
            .receive::<_, _, BUFFER>(&mut self.transport, consumer).await
    }
}
