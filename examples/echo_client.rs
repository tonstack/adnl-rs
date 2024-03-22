use adnl::{AdnlPeer, AdnlRawPublicKey};
use futures::{SinkExt, StreamExt};
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let public_key_hex = env::args()
        .nth(2)
        .unwrap_or_else(|| "691a14528fb2911839649c489cb4cbec1f4aa126c244c0ea2ac294eb568a7037".to_string());

    let remote_public = AdnlRawPublicKey::try_from(&*hex::decode(public_key_hex)?)?;

    // act as a client: connect to ADNL server and perform handshake
    let mut client = AdnlPeer::connect(&remote_public, addr).await.expect("adnl connect");

    // send over ADNL
    client.send("hello".as_bytes().into()).await.expect("send");

    // receive result
    let result = client.next().await.expect("packet must be received")?;

    println!("received: {}", String::from_utf8(result.to_vec()).unwrap());
    Ok(())
}
