use std::net::SocketAddrV4;
use anyhow::{anyhow, Context};
use crate::{AdnlBuilder, AdnlError, AdnlHandshake, AdnlPublicKey, AdnlReceiver, AdnlSender};
use tokio::io::{AsyncReadExt, AsyncWriteExt, empty};
use tokio::net::TcpStream;
use x25519_dalek::StaticSecret;

/// Abstraction over [`AdnlSender`] and [`AdnlReceiver`] to keep things simple
pub struct AdnlClient<T: AsyncReadExt + AsyncWriteExt> {
    sender: AdnlSender,
    receiver: AdnlReceiver,
    transport: T,
}

impl AdnlClient<TcpStream> {
    /// Create ADNL client use random private key and random AES params
    pub async fn connect(
        ls_public: &str,
        ls_ip: &str,
        ls_port: u16,
    ) -> anyhow::Result<AdnlClient<TcpStream>> {
        // decode liteserver public key
        let remote_public: [u8; 32] = base64::decode(ls_public)
            .context("Error decode base64")?
            .try_into().map_err(|_| anyhow!("Bad public key length"))?;

        // generate private key
        let local_secret = StaticSecret::new(rand::rngs::OsRng);

        // use TcpStream as transport for our ADNL connection
        let transport = TcpStream::connect(SocketAddrV4::new(ls_ip.parse()?, ls_port)).await
            .context("Connection error")?;

        // build handshake using random session keys, encrypt it with ECDH(local_secret, remote_public)
        // then perform handshake over our TcpStream
        let client = AdnlBuilder::with_random_aes_params(&mut rand::rngs::OsRng)
            .perform_ecdh(local_secret, remote_public)
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
