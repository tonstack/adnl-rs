//! Adopted from https://github.com/tokio-rs/tokio/blob/b32826bc937a34e4d871c89bb2c3711ed3e20cdc/examples/echo.rs

use std::{env, error::Error};

use adnl::{AdnlPeer, AdnlPrivateKey, AdnlPublicKey};
use tokio::net::TcpListener;
use x25519_dalek::StaticSecret;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    // ADNL: get private key from environment variable KEY or use default insecure one
    let private_key_hex = env::var("KEY").unwrap_or_else(|_| "69734189c0348245a70eb5335e12bfd75dd4cffc42baf32773e8f994ff5cf7c2".to_string());
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex)?.try_into().unwrap();
    let private_key = StaticSecret::from(private_key_bytes);

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop.
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    // ADNL: print public key and adnl address associated with given private key
    println!("Public key is: {}", hex::encode(private_key.public().as_bytes()));
    println!("Address is: {}", hex::encode(private_key.public().address().as_bytes()));

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, _) = listener.accept().await?;

        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.

        let private_key = private_key.clone();
        tokio::spawn(async move {
            // ADNL: handle handshake
            let mut adnl_server = AdnlPeer::handle_handshake(socket, &private_key).await.expect("handshake failed");

            let mut buf = vec![0; 1024];

            // In a loop, read data from the socket and write the data back.
            loop {
                let n = adnl_server.receive(&mut buf)
                    .await
                    .expect("failed to read data from socket");

                adnl_server
                    .send(&mut buf[..n])
                    .await
                    .expect("failed to write data to socket");
            }
        });
    }
}