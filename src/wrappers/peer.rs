use crate::{AdnlBuilder, AdnlError, AdnlHandshake, AdnlPrivateKey, AdnlPublicKey, AdnlReceiver, AdnlSender};
use tokio::io::{empty, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use x25519_dalek::StaticSecret;

/// Abstraction over [`AdnlSender`] and [`AdnlReceiver`] to keep things simple
pub struct AdnlPeer<T: AsyncReadExt + AsyncWriteExt> {
    sender: AdnlSender,
    receiver: AdnlReceiver,
    transport: T,
}

impl AdnlPeer<TcpStream> {
    /// Create ADNL client using random private key and random AES params
    #[cfg(feature = "dalek")]
    pub async fn connect<P: AdnlPublicKey, A: ToSocketAddrs>(
        ls_public: &P,
        ls_addr: A,
    ) -> Result<AdnlPeer<TcpStream>, AdnlError> {
        // generate private key
        let local_secret = StaticSecret::new(rand::rngs::OsRng);

        // use TcpStream as transport for our ADNL connection
        let transport = TcpStream::connect(ls_addr).await?;

        // build handshake using random session keys, encrypt it with ECDH(local_secret, remote_public)
        // then perform handshake over our TcpStream
        let client = AdnlBuilder::with_random_aes_params(&mut rand::rngs::OsRng)
            .perform_ecdh(&local_secret, ls_public)
            .perform_handshake(transport)
            .await?;
        Ok(client)
    }
}

impl<T: AsyncReadExt + AsyncWriteExt + Unpin> AdnlPeer<T> {
    /// Act as a client: send `handshake` over `transport` and check that handshake was successful
    /// Returns client part of ADNL connection
    pub async fn perform_handshake<P: AdnlPublicKey>(
        mut transport: T,
        handshake: &AdnlHandshake<P>,
    ) -> Result<Self, AdnlError> {
        // send handshake
        transport
            .write_all(&handshake.to_bytes())
            .await
            .map_err(AdnlError::WriteError)?;

        // receive empty message to ensure that server knows our AES keys
        let mut client = Self {
            sender: AdnlSender::new(handshake.aes_params()),
            receiver: AdnlReceiver::new(handshake.aes_params()),
            transport,
        };
        let mut empty = empty();
        client
            .receive_with_buffer::<_, 0>(&mut empty)
            .await?;
        Ok(client)
    }

    /// Act as a server: receive handshake over transport. 
    /// Verifies following things:
    /// 1) target ADNL address matches associated with provided private key
    /// 2) integrity of handshake is not compromised
    pub async fn handle_handshake<S: AdnlPrivateKey>(mut transport: T, private_key: &S) -> Result<Self, AdnlError> {
        // receive handshake
        let mut packet = [0u8; 256];
        transport.read_exact(&mut packet).await.map_err(AdnlError::ReadError)?;
        let handshake = AdnlHandshake::decrypt_from_raw(&packet, private_key)?;

        let mut server = Self {
            sender: AdnlSender::new(handshake.aes_params()),
            receiver: AdnlReceiver::new(handshake.aes_params()),
            transport,
        };

        // send empty packet to proof knowledge of AES keys
        server.send(&mut []).await?;

        Ok(server)
    }

    /// Send `data` to another peer with random nonce
    pub async fn send(&mut self, data: &mut [u8]) -> Result<(), AdnlError> {
        self.sender
            .send(&mut self.transport, &mut rand::random(), data)
            .await
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
    ) -> Result<usize, AdnlError> {
        self.receiver
            .receive::<_, _, 8192>(&mut self.transport, consumer)
            .await
    }

    /// Receive data from another peer into `consumer` which will process the data. Set `BUFFER`
    /// according to your memory requirements, recommended size is 8192 bytes.
    pub async fn receive_with_buffer<C: AsyncWriteExt + Unpin, const BUFFER: usize>(
        &mut self,
        consumer: &mut C,
    ) -> Result<usize, AdnlError> {
        self.receiver
            .receive::<_, _, BUFFER>(&mut self.transport, consumer)
            .await
    }
}