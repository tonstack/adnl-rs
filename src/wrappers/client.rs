use crate::{AdnlBuilder, AdnlError, AdnlHandshake, AdnlPublicKey, AdnlReceiver, AdnlSender};
use tokio::io::{AsyncReadExt, AsyncWriteExt, empty};
use tokio::net::{TcpStream, ToSocketAddrs};
use x25519_dalek::StaticSecret;

/// Abstraction over [`AdnlSender`] and [`AdnlReceiver`] to keep things simple
pub struct AdnlClient<T: AsyncReadExt + AsyncWriteExt> {
    sender: AdnlSender,
    receiver: AdnlReceiver,
    transport: T,
}

impl AdnlClient<TcpStream> {
    /// Create ADNL client use random private key and random AES params
    #[cfg(feature = "dalek")]
    pub async fn connect<P: AdnlPublicKey, A: ToSocketAddrs>(
        ls_public: P,
        ls_addr: A,
    ) -> Result<AdnlClient<TcpStream>, AdnlError> {
        // generate private key
        let local_secret = StaticSecret::new(rand::rngs::OsRng);

        // use TcpStream as transport for our ADNL connection
        let transport = TcpStream::connect(ls_addr).await?;

        // build handshake using random session keys, encrypt it with ECDH(local_secret, remote_public)
        // then perform handshake over our TcpStream
        let client = AdnlBuilder::with_random_aes_params(&mut rand::rngs::OsRng)
            .perform_ecdh(local_secret, ls_public)
            .perform_handshake(transport).await?;
        Ok(client)
    }
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
        let mut empty = empty();
        client.receiver.receive::<_, _, 0>(&mut client.transport, &mut empty).await?;
        Ok(client)
    }
    
    /// Send `data` to another peer with random nonce
    pub async fn send(
        &mut self,
        data: &mut [u8],
    ) -> Result<(), AdnlError> {
        self.sender.send(&mut self.transport, &mut rand::random(), data).await
    }

    /// Send `data` to another peer. Random `nonce` must be provided to eliminate bit-flipping attacks.
    pub async fn send_with_nonce(
        &mut self,
        data: &mut [u8],
        nonce: &mut [u8; 32],
    ) -> Result<(), AdnlError> {
        self.sender.send(&mut self.transport, nonce, data).await
    }
    
    
    /// Receive data from another peer into `consumer` which will process the data with 
    /// a `BUFFER` size of 8192 bytes.
    pub async fn receive<C: AsyncWriteExt + Unpin>(
        &mut self,
        consumer: &mut C,
    ) -> Result<(), AdnlError> {
        self.receiver
            .receive::<_, _, 8192>(&mut self.transport, consumer).await
    }

    /// Receive data from another peer into `consumer` which will process the data. Set `BUFFER`
    /// according to your memory requirements, recommended size is 8192 bytes.
    pub async fn receive_with_buffer<C: AsyncWriteExt + Unpin, const BUFFER: usize>(
        &mut self,
        consumer: &mut C,
    ) -> Result<(), AdnlError> {
        self.receiver
            .receive::<_, _, BUFFER>(&mut self.transport, consumer).await
    }
}
