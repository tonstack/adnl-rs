use crate::{AdnlAddress, AdnlAesParams, AdnlHandshake, AdnlPublicKey, AdnlSecret};

use crate::helper_types::{AdnlPrivateKey, CryptoRandom};

/// Builder of [`AdnlHandshake`] structure, which then can be transformed into [`AdnlClient`]
pub struct AdnlBuilder {
    aes_params: AdnlAesParams,
}

impl AdnlBuilder {
    /// Use specified session parameters. It is recommended to use random parameters.
    pub fn with_static_aes_params(aes_params: AdnlAesParams) -> Self {
        Self { aes_params }
    }

    /// Use random session parameters (recommended).
    pub fn with_random_aes_params<R: CryptoRandom>(rng: &mut R) -> Self {
        Self {
            aes_params: {
                let mut buffer = [0u8; 160];
                rng.fill_bytes(&mut buffer);
                AdnlAesParams::from(buffer)
            },
        }
    }

    /// Specify sender, receiver, and secret on which they already agreed.
    pub fn use_static_ecdh<P: AdnlPublicKey>(
        self,
        sender_public: P,
        receiver_address: AdnlAddress,
        ecdh_secret: AdnlSecret,
    ) -> AdnlHandshake<P> {
        AdnlHandshake::new(
            receiver_address,
            sender_public,
            ecdh_secret,
            self.aes_params,
        )
    }

    /// Perform key agreement using sender private key and receiver public
    pub fn perform_ecdh<S, P>(
        self,
        sender_private: S,
        receiver_public: P,
    ) -> AdnlHandshake<<S as AdnlPrivateKey>::PublicKey>
    where
        S: AdnlPrivateKey,
        P: AdnlPublicKey,
    {
        AdnlHandshake::new(
            receiver_public.address(),
            sender_private.public(),
            sender_private.key_agreement(receiver_public),
            self.aes_params,
        )
    }
}
