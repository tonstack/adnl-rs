use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{AdnlBuilder, AdnlError, AdnlHandshake, AdnlPrivateKey, AdnlPublicKey};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Decoder, Framed};
use x25519_dalek::StaticSecret;
use futures::{Sink, SinkExt, Stream, StreamExt};

use crate::primitives::codec::AdnlCodec;

/// Abstraction over [`AdnlSender`] and [`AdnlReceiver`] to keep things simple
#[pin_project]
pub struct AdnlPeer<T> where T: AsyncRead + AsyncWrite {
    #[pin]
    stream: Framed<T, AdnlCodec>,
}

impl AdnlPeer<TcpStream> {
    /// Create ADNL client using random private key and random AES params
    #[cfg(feature = "dalek")]
    pub async fn connect<P: AdnlPublicKey, A: ToSocketAddrs>(
        ls_public: &P,
        ls_addr: A,
    ) -> Result<AdnlPeer<TcpStream>, AdnlError> {
        // generate private key
        let local_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);

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
    pub async fn perform_handshake<P: AdnlPublicKey>(mut transport: T, handshake: &AdnlHandshake<P>) -> Result<Self, AdnlError> {
        // send handshake
        transport
            .write_all(&handshake.to_bytes())
            .await
            .map_err(AdnlError::IoError)?;

        let mut stream = handshake.make_codec().framed(transport);

        // receive empty message to ensure that server knows our AES keys
        if let Some(x) = stream.next().await {
            x?;
            Ok(Self { stream })
        } else {
            Err(AdnlError::EndOfStream)
        }
    }

    /// Act as a server: receive handshake over transport. 
    /// Verifies following things:
    /// 1) target ADNL address matches associated with provided private key
    /// 2) integrity of handshake is not compromised
    pub async fn handle_handshake<S: AdnlPrivateKey>(mut transport: T, private_key: &S) -> Result<Self, AdnlError> {
        // receive handshake
        let mut packet = [0u8; 256];
        transport.read_exact(&mut packet).await.map_err(AdnlError::IoError)?;
        let handshake = AdnlHandshake::decrypt_from_raw(&packet, private_key)?;

        let mut server = Self {
            stream: handshake.make_codec().framed(transport),
        };

        // send empty packet to proof knowledge of AES keys
        server.send(Bytes::new()).await?;

        Ok(server)
    }
}

impl<T> Stream for AdnlPeer<T> where T: AsyncRead + AsyncWrite
{
    type Item = Result<Bytes, AdnlError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }
}

impl<T> Sink<Bytes> for AdnlPeer<T> where T: AsyncWrite + AsyncRead
{
    type Error = AdnlError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.project().stream.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_close(cx)
    }
}