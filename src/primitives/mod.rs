use aes::Aes256;
use ctr::Ctr128BE;

pub type AdnlAes = Ctr128BE<Aes256>;

pub mod send;
pub mod receive;
pub mod handshake;
