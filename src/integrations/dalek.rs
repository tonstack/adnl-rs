use crate::{AdnlPublicKey, AdnlSecret};
use x25519_dalek::{PublicKey, SharedSecret};

impl From<PublicKey> for AdnlPublicKey {
    fn from(public_key: PublicKey) -> Self {
        Self(public_key.to_bytes())
    }
}

impl From<SharedSecret> for AdnlSecret {
    fn from(secret: SharedSecret) -> Self {
        Self(secret.to_bytes())
    }
}