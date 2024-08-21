# ADNL

[![crates.io](https://img.shields.io/crates/v/adnl.svg)](https://crates.io/crates/adnl)
[![documentation](https://docs.rs/adnl/badge.svg)](https://docs.rs/adnl)

Minimal client-server ADNL implementation in Rust. Specification of ADNL is available [here](https://github.com/tonstack/ton-docs/blob/main/ADNL/README.md).

## Quickstart
Run this example: `cargo run --example time`

```rust
use adnl::AdnlPeer;
use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // decode liteserver public key
    let remote_public = base64::engine::general_purpose::STANDARD.decode("n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=")?;

    // act as a client: connect to ADNL server and perform handshake
    let mut client = AdnlPeer::connect(remote_public, "5.9.10.47:19949").await?;

    // already serialized TL with getTime query
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
```
