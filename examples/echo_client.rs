use adnl::{AdnlPeer, AdnlRawPublicKey};
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let public_key_hex = env::args()
        .nth(2)
        .unwrap_or_else(|| "b7d8e88f4033eff806e2f5dff3c785be7dd038c923146e2d9fe80e4fe3cb8805".to_string());

    let remote_public = AdnlRawPublicKey::try_from(&*hex::decode(public_key_hex)?)?;

    // act as a client: connect to ADNL server and perform handshake
    let mut client = AdnlPeer::connect(&remote_public, addr).await?;

    // send over ADNL
    client.send(&mut "hello".as_bytes().to_vec()).await?;

    // receive result into vector
    let mut result = Vec::<u8>::new();
    client.receive(&mut result).await?;

    println!("received: {}", String::from_utf8(result).unwrap());
    Ok(())
}
