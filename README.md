# ADNL

[![crates.io](https://img.shields.io/crates/v/adnl.svg)](https://crates.io/crates/adnl)
[![documentation](https://docs.rs/adnl/badge.svg)](https://docs.rs/adnl)

Minimal client-server ADNL implementation in Rust. Specification of ADNL is available [here](https://github.com/tonstack/ton-docs/blob/main/ADNL/README.md).

| Feature      | Status                          |
|--------------|---------------------------------|
| ADNL Client  | ✅ Implemented                   |
| ADNL Server  | ❌ Not implemented               |
| async        | ✅ Implemented                   |
| ed25519 libs | curve25519_dalek + x25519_dalek |

## Quickstart
Run this example: `cargo run --example time`

```rust
use adnl::AdnlClient;
use anyhow::{anyhow, Context, Result};
use std::net::SocketAddrV4;


#[tokio::main]
async fn main() -> Result<()> {
    // decode liteserver public key
    let remote_public: [u8; 32] = base64::decode("JhXt7H1dZTgxQTIyGiYV4f9VUARuDxFl/1kVBjLSMB8=")
        .context("Error decode base64")?
        .try_into().map_err(|_| anyhow!("Bad public key length"))?;

    let ls_ip = "65.21.74.140";
    let ls_port = 46427;
    // create AdnlClient
    let mut client =
        AdnlClient::connect(remote_public, SocketAddrV4::new(ls_ip.parse()?, ls_port)).await?;

    // already serialized TL with gettime query
    let mut query = hex::decode("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")?;

    // send over ADNL, use random nonce
    client.send(&mut query).await?;

    // receive result into vector, use 8192 bytes buffer
    let mut result = Vec::<u8>::new();
    client.receive(&mut result).await?;

    // get time from serialized TL answer
    println!(
        "received: {}",
        u32::from_le_bytes(result[result.len() - 7..result.len() - 3].try_into()?)
    );
    Ok(())
}
```
