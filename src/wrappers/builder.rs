use crate::{AdnlAesParams, AdnlHandshake, AdnlPublicKey, AdnlAddress, AdnlSecret};

use crate::helper_types::CryptoRandom;

enum AesOptions<'a> {
    StaticParams(AdnlAesParams),
    RandomParams(&'a mut dyn CryptoRandom),
}

pub struct AdnlBuilder<'a> {
    aes_options: AesOptions<'a>,
}

impl<'a> AdnlBuilder<'a> {
    pub fn with_static_aes_params(aes_params: AdnlAesParams) -> Self {
        Self {
            aes_options: AesOptions::StaticParams(aes_params)
        }
    }

    pub fn with_random_aes_params(rng: &'a mut dyn CryptoRandom) -> Self {
        Self {
            aes_options: AesOptions::RandomParams(rng)
        }
    }

    pub fn use_static_ecdh<S, R, E>(self, sender_public: S, receiver_address: R, ecdh_secret: E) -> AdnlHandshake
        where S: Into<AdnlPublicKey>, R: Into<AdnlAddress>, E: Into<AdnlSecret>
    {
        let sender_public = sender_public.into();
        let receiver_address = receiver_address.into();
        let ecdh_secret = ecdh_secret.into();

        // make aes params
        let aes_params = match self.aes_options {
            AesOptions::StaticParams(aes_params) => aes_params,
            AesOptions::RandomParams(rng) => {
                let mut buffer = [0u8; 160];
                rng.fill_bytes(&mut buffer);
                AdnlAesParams::from(buffer)
            }
        };

        AdnlHandshake::new(receiver_address, sender_public, ecdh_secret, aes_params)
    }
}
