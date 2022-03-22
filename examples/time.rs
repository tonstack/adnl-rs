use std::error::Error;
use std::net::{SocketAddrV4, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use adnl::{AdnlAddress, AdnlBuilder, AdnlClient, AdnlPublicKey};

pub fn to_montgomery(pub_key: &[u8; 32]) -> PublicKey {
    CompressedEdwardsY::from_slice(pub_key).decompress().unwrap().to_montgomery().to_bytes().into()
}

pub fn to_edwards(pub_key: &PublicKey) -> [u8; 32] {
    MontgomeryPoint(pub_key.to_bytes()).to_edwards(0).unwrap().compress().to_bytes()
}

pub fn connect(ls_public: &str, ls_ip: &str, ls_port: u16) -> Result<AdnlClient<TcpStream>, Box<dyn Error>> {
    let remote_public: [u8; 32] = base64::decode(ls_public)?.try_into().unwrap();
    let remote_address = AdnlAddress::from(remote_public.into());
    let local_secret = EphemeralSecret::new(rand::rngs::OsRng);
    let transport = TcpStream::connect(SocketAddrV4::new(ls_ip.parse()?, ls_port))?;
    let client = AdnlBuilder::with_random_aes_params(&mut rand::rngs::OsRng)
        .use_static_ecdh(to_edwards(&PublicKey::from(&local_secret)),
                         remote_address,
                         local_secret.diffie_hellman(&to_montgomery(&remote_public)))
        .perform_handshake(transport).map_err(|e| format!("{:?}", e))?;
    Ok(client)
}

fn main() -> Result<(), Box<dyn Error>> {
    // create AdnlClient
    let mut client = connect("JhXt7H1dZTgxQTIyGiYV4f9VUARuDxFl/1kVBjLSMB8=", "65.21.74.140", 46427)?;

    // already serialized TL
    let mut query = hex::decode("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")?;

    // send over adnl, use random nonce
    client.send(&mut query, &mut rand::random()).map_err(|e| format!("{:?}", e))?;

    // receive result, use 8192 bytes buffer
    let mut result = Vec::<u8>::new();
    client.receive::<_, 8192>(&mut result).map_err(|e| format!("{:?}", e))?;

    // get time from serialized TL
    println!("received: {}", u32::from_le_bytes(result[result.len() - 7..result.len() - 3].try_into()?));
    Ok(())
}