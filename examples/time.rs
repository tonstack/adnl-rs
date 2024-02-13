use adnl::AdnlClient;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // create AdnlClient
    let mut client = AdnlClient::connect(
        "JhXt7H1dZTgxQTIyGiYV4f9VUARuDxFl/1kVBjLSMB8=",
        "65.21.74.140",
        46427,
    ).await?;

    // already serialized TL with gettime query
    let mut query = hex::decode("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")?;

    // send over ADNL, use random nonce
    client.send(&mut query, &mut rand::random()).await?;

    // receive result into vector, use 8192 bytes buffer
    let mut result = Vec::<u8>::new();
    client.receive::<_, 8192>(&mut result).await?;

    // get time from serialized TL answer
    println!(
        "received: {}",
        u32::from_le_bytes(result[result.len() - 7..result.len() - 3].try_into()?)
    );
    Ok(())
}
