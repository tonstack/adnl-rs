use crate::{AdnlAesParams, AdnlHandshake, AdnlPublicKey, AdnlAddress, AdnlSecret};

use crate::helper_types::{AdnlPrivateKey, CryptoRandom};

pub struct AdnlBuilder {
    aes_params: AdnlAesParams,
}

impl AdnlBuilder {
    pub fn with_static_aes_params(aes_params: AdnlAesParams) -> Self {
        Self {
            aes_params
        }
    }

    pub fn with_random_aes_params<R: CryptoRandom>(rng: &mut R) -> Self {
        Self {
            aes_params: {
                let mut buffer = [0u8; 160];
                rng.fill_bytes(&mut buffer);
                AdnlAesParams::from(buffer)
            }
        }
    }

    pub fn use_static_ecdh<P: AdnlPublicKey>(self, sender_public: P, receiver_address: AdnlAddress, ecdh_secret: AdnlSecret) -> AdnlHandshake<P>
    {
        AdnlHandshake::new(receiver_address, sender_public, ecdh_secret, self.aes_params)
    }

    pub fn perform_ecdh<S, P>(self, sender_private: S, receiver_public: P) -> AdnlHandshake<<S as AdnlPrivateKey>::PublicKey>
        where S: AdnlPrivateKey, P: AdnlPublicKey {
        AdnlHandshake::new(receiver_public.address(), sender_private.public(), sender_private.key_agreement(receiver_public), self.aes_params)
    }
}
