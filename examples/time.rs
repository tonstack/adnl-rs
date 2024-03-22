use adnl::{AdnlPeer, AdnlRawPublicKey};
use futures::{SinkExt, StreamExt};
use std::{error::Error, net::SocketAddrV4};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // decode liteserver public key
    let remote_public = AdnlRawPublicKey::try_from(&*base64::decode("JhXt7H1dZTgxQTIyGiYV4f9VUARuDxFl/1kVBjLSMB8=")?)?;

    let ls_ip = "65.21.74.140";
    let ls_port = 46427;
    // act as a client: connect to ADNL server and perform handshake
    let mut client = AdnlPeer::connect(&remote_public, SocketAddrV4::new(ls_ip.parse()?, ls_port)).await?;

    // already serialized TL with gettime query
    let query = hex::decode("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")?;

    // send over ADNL
    client.send(query.into()).await?;

    // receive result
    let result = client.next().await.ok_or_else(|| "no result")??;

    // get time from serialized TL answer
    println!(
        "received: {}",
        u32::from_le_bytes(result[result.len() - 7..result.len() - 3].try_into()?)
    );
    Ok(())
}
