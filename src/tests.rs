extern crate alloc;

use super::*;
use alloc::vec::Vec;

#[test]
fn test_handshake_1() {
    let aes_params = hex::decode("b3d529e34b839a521518447b68343aebaae9314ac95aaacfdb687a2163d1a98638db306b63409ef7bc906b4c9dc115488cf90dfa964f520542c69e1a4a495edf9ae9ee72023203c8b266d552f251e8d724929733428c8e276ab3bd6291367336a6ab8dc3d36243419bd0b742f76691a5dec14edbd50f7c1b58ec961ae45be58cbf6623f3ec9705bd5d227761ec79cee377e2566ff668f863552bddfd6ff3a16b").unwrap();
    let remote_public =
        hex::decode("2615edec7d5d6538314132321a2615e1ff5550046e0f1165ff59150632d2301f").unwrap();
    let ecdh =
        hex::decode("1f4d11789a5559b238f7ac8213e112184f16a97593b4a059c878af288a784b79").unwrap();
    let expected_handshake = hex::decode("a3fc70bfeff13b04ed4f2581045ff95a385df762eb82ab9902066061c2e6033e67d45a90e775d8f78d9feb9bdd222446e07c3de4a54e29220d18c18c5b340db36c06a61a8eb209b2b4f9d7359d76e3e0722024579d2b8bc920a6506238d6d88d14a880eb99b4996df8a11bb1a7124e39825848c74fc3d7bfab034e71dbc2e2d1606c14db1b04bb25b544a83b47815e9ec0590a9f4dd011b4bae7b01ddb376570d6641919e63933bf297a073b8febfae0c4dd298215e5db929c6764c43502874b7b5af6380fd52d3fd072b7046d6ccadecc771f54b461b5a157fe3e059df9575dc72dfc89e36b26a7cf9a4e7925c96e88d5342c139154c4a6e4e9d683d9373e3a").unwrap();
    let local_public =
        hex::decode("67d45a90e775d8f78d9feb9bdd222446e07c3de4a54e29220d18c18c5b340db3").unwrap();
    test_handshake(
        remote_public,
        local_public,
        ecdh,
        aes_params,
        expected_handshake,
    );
}

#[test]
fn test_handshake_2() {
    let aes_params = hex::decode("7e3c66de7c64d4bee4368e69560101991db4b084430a336cffe676c9ac0a795d8c98367309422a8e927e62ed657ba3eaeeb6acd3bbe5564057dfd1d60609a25a48963cbb7d14acf4fc83ec59254673bc85be22d04e80e7b83c641d37cae6e1d82a400bf159490bbc0048e69234ad89e999d792eefdaa56734202546d9188706e95e1272267206a8e7ee1f7c077f76bd26e494972e34d72e257bf20364dbf39b0").unwrap();
    let remote_public =
        hex::decode("2615edec7d5d6538314132321a2615e1ff5550046e0f1165ff59150632d2301f").unwrap();
    let ecdh =
        hex::decode("10a28a56cce723b2ab75aeba51039f5f3f72bca49f22b7f8039690811bb0606e").unwrap();
    let expected_handshake = hex::decode("a3fc70bfeff13b04ed4f2581045ff95a385df762eb82ab9902066061c2e6033ed86dac237d94b1b611dcac497f952edb63756910dbf625f5c5806e159d1047270f372a88fd1f76b0a574620cf47202369359bdeff8e709d6c0578cf08d2499cb949ecaaf892f11fc772932182269f9e5f2f44150066ae65fbb5fc9f51dab26825bd6fd4d72de9ccc80bbddcb9d47f9c3cfd00b80a5d9faf15007abb480f9fd85e2f671484e82f3b67f58197c5438dab575062faa9acd821ca6a10e7061c40535112650f1730d03484de0d01aa7912ed64655e672bd077c1f1e50b231556ecfd5e5009f47804c317abec6310165a6618125a2204b0370d40e672e1a640817b894").unwrap();
    let local_public =
        hex::decode("d86dac237d94b1b611dcac497f952edb63756910dbf625f5c5806e159d104727").unwrap();
    test_handshake(
        remote_public,
        local_public,
        ecdh,
        aes_params,
        expected_handshake,
    );
}

fn test_handshake(
    remote_public: Vec<u8>,
    local_public: Vec<u8>,
    ecdh: Vec<u8>,
    aes_params: Vec<u8>,
    expected_handshake: Vec<u8>,
) {
    // test serializing
    let aes_params_raw: [u8; 160] = aes_params.try_into().unwrap();
    let aes_params = AdnlAesParams::from(aes_params_raw);
    let remote_public: [u8; 32] = remote_public.try_into().unwrap();
    let local_public: [u8; 32] = local_public.try_into().unwrap();
    let ecdh_raw: [u8; 32] = ecdh.try_into().unwrap();
    let ecdh = AdnlSecret::from(ecdh_raw);
    let handshake = AdnlHandshake::new(remote_public.address(), local_public, ecdh, aes_params);
    assert_eq!(
        handshake.to_bytes(),
        expected_handshake.as_slice(),
        "handshake is not the same!"
    );

    // test deserializing
    struct DummyKey {
        ecdh: [u8; 32],
        public: [u8; 32]
    }

    impl AdnlPrivateKey for DummyKey {
        type PublicKey = [u8; 32];

        fn key_agreement<P: AdnlPublicKey>(&self, _their_public: P) -> AdnlSecret {
            AdnlSecret::from(self.ecdh)
        }

        fn public(&self) -> Self::PublicKey {
            self.public
        }
    }

    let key = DummyKey { ecdh: ecdh_raw, public: remote_public };
    let handshake2 = AdnlHandshake::decrypt_from_raw(&expected_handshake, &key).expect("valid handshake");
    assert_eq!(handshake2.aes_params().to_bytes(), aes_params_raw, "aes_params mismatch");
    assert_eq!(handshake2.receiver(), &remote_public.address(), "receiver mismatch");
    assert_eq!(handshake2.sender(), &local_public, "sender mismatch");
    assert_eq!(&handshake2.to_bytes(), expected_handshake.as_slice(), "reencryption failed");
}

#[tokio::test]
async fn test_send_1() {
    let aes_params = hex::decode("b3d529e34b839a521518447b68343aebaae9314ac95aaacfdb687a2163d1a98638db306b63409ef7bc906b4c9dc115488cf90dfa964f520542c69e1a4a495edf9ae9ee72023203c8b266d552f251e8d724929733428c8e276ab3bd6291367336a6ab8dc3d36243419bd0b742f76691a5dec14edbd50f7c1b58ec961ae45be58cbf6623f3ec9705bd5d227761ec79cee377e2566ff668f863552bddfd6ff3a16b").unwrap();
    let nonce =
        hex::decode("9a5ecd5d9afdfff2823e7520fa1c338f2baf1a21f51e6fdab0491d45a50066f7").unwrap();
    let buffer = hex::decode("7af98bb471ff48e9b263959b17a04faae4a23501380d2aa932b09eac6f9846fcbae9bbcb0cdf068c7904345aad16000000000000").unwrap();
    let expected_packet = hex::decode("250d70d08526791bc2b6278ded7bf2b051afb441b309dda06f76e4419d7c31d4d5baafc4ff71e0ebabe246d4ea19e3e579bd15739c8fc916feaf46ea7a6bc562ed1cf87c9bf4220eb037b9a0b58f663f0474b8a8b18fa24db515e41e4b02e509d8ef261a27ba894cbbecc92e59fc44bf5ff7c8281cb5e900").unwrap();
    test_send(aes_params, nonce, buffer, expected_packet).await;
}

#[tokio::test]
async fn test_send_2() {
    let aes_params = hex::decode("7e3c66de7c64d4bee4368e69560101991db4b084430a336cffe676c9ac0a795d8c98367309422a8e927e62ed657ba3eaeeb6acd3bbe5564057dfd1d60609a25a48963cbb7d14acf4fc83ec59254673bc85be22d04e80e7b83c641d37cae6e1d82a400bf159490bbc0048e69234ad89e999d792eefdaa56734202546d9188706e95e1272267206a8e7ee1f7c077f76bd26e494972e34d72e257bf20364dbf39b0").unwrap();
    let nonce =
        hex::decode("d36d0683da23e62910fa0e8a9331dfc257db4cde0ba8d63893e88ac4de7d8d6c").unwrap();
    let buffer = hex::decode("7af98bb47bcae111ea0e56457826b1aec7f0f59b9b6579678b3db3839d17b63eb60174f20cdf068c7904345aad16000000000000").unwrap();
    let expected_packet = hex::decode("24c709a0f676750ddaeafc8564d84546bfc831af27fb66716de382a347a1c32adef1a27e597c8a07605a09087fff32511d314970cad3983baefff01e7ee51bb672b17f7914a6d3f229a13acb14cdc14d98beae8a1e96510756726913541f558c2ffac63ed6cb076d0e888c3c0bb014d9f229c2a3f62e0847").unwrap();
    test_send(aes_params, nonce, buffer, expected_packet).await;
}

async fn test_send(aes_params: Vec<u8>, nonce: Vec<u8>, buffer: Vec<u8>, expected_packet: Vec<u8>) {
    let mut nonce = nonce.try_into().unwrap();
    let mut buffer = buffer;
    let aes_params: [u8; 160] = aes_params.try_into().unwrap();
    let aes_params = AdnlAesParams::from(aes_params);
    let mut protocol_client = AdnlSender::new(&aes_params);
    let mut packet = Vec::<u8>::new();
    let _result = protocol_client
        .send(&mut packet, &mut nonce, &mut buffer)
        .await;
    assert_eq!(
        packet.as_slice(),
        &expected_packet,
        "outcoming packet is wrong"
    );
}

#[tokio::test]
async fn test_recv_1() {
    let encrypted_data = hex::decode("81e95e433c87c9ad2a716637b3a12644fbfb12dbd02996abc40ed2beb352483d6ecf9e2ad181a5abde4d4146ca3a8524739d3acebb2d7599cc6b81967692a62118997e16").unwrap();
    let expected_data = Vec::new();
    let aes_params = hex::decode("b3d529e34b839a521518447b68343aebaae9314ac95aaacfdb687a2163d1a98638db306b63409ef7bc906b4c9dc115488cf90dfa964f520542c69e1a4a495edf9ae9ee72023203c8b266d552f251e8d724929733428c8e276ab3bd6291367336a6ab8dc3d36243419bd0b742f76691a5dec14edbd50f7c1b58ec961ae45be58cbf6623f3ec9705bd5d227761ec79cee377e2566ff668f863552bddfd6ff3a16b").unwrap();
    let aes_params: [u8; 160] = aes_params.try_into().unwrap();
    let aes_params = AdnlAesParams::from(aes_params);
    let mut protocol_client = AdnlReceiver::new(&aes_params);
    test_recv(&mut protocol_client, encrypted_data, expected_data).await;
    let encrypted_data = hex::decode("4b72a32bf31894cce9ceffd2dd97176e502946524e45e62689bd8c5d31ad53603c5fd3b402771f707cd2747747fad9df52e6c23ceec9fa2ee5b0f68b61c33c7790db03d1c593798a29d716505cea75acdf0e031c25447c55c4d29d32caab29bd5a0787644843bafc04160c92140aab0ecc990927").unwrap();
    let expected_data = hex::decode("1684ac0f71ff48e9b263959b17a04faae4a23501380d2aa932b09eac6f9846fcbae9bbcb080d0053e9a3ac3062000000").unwrap();
    test_recv(&mut protocol_client, encrypted_data, expected_data).await;
}

#[tokio::test]
async fn test_recv_2() {
    let encrypted_data = hex::decode("b75dcf27582beb4031d6d3700c9b7925bf84a78f2bd16b186484d36427a8824ac86e27cea81eb5bcbac447a37269845c65be51babd11c80627f81b4247f84df16d05c4f1").unwrap();
    let expected_data = Vec::new();
    let aes_params = hex::decode("7e3c66de7c64d4bee4368e69560101991db4b084430a336cffe676c9ac0a795d8c98367309422a8e927e62ed657ba3eaeeb6acd3bbe5564057dfd1d60609a25a48963cbb7d14acf4fc83ec59254673bc85be22d04e80e7b83c641d37cae6e1d82a400bf159490bbc0048e69234ad89e999d792eefdaa56734202546d9188706e95e1272267206a8e7ee1f7c077f76bd26e494972e34d72e257bf20364dbf39b0").unwrap();
    let aes_params: [u8; 160] = aes_params.try_into().unwrap();
    let aes_params = AdnlAesParams::from(aes_params);
    let mut protocol_client = AdnlReceiver::new(&aes_params);
    test_recv(&mut protocol_client, encrypted_data, expected_data).await;
    let encrypted_data = hex::decode("77ebea5a6e6c8758e7703d889abad16e7e3c4e0c10c4e81ca10d0d9abddabb6f008905133a070ff825ad3f4b0ae969e04dbd8b280864d3d2175f3bc7cf3deb31de5497fa43997d8e2acafb9a31de2a22ecb279b5854c00791216e39c2e65863539d82716fc020e9647b2dd99d0f14e4f553b645f").unwrap();
    let expected_data = hex::decode("1684ac0f7bcae111ea0e56457826b1aec7f0f59b9b6579678b3db3839d17b63eb60174f2080d0053e90bb03062000000").unwrap();
    test_recv(&mut protocol_client, encrypted_data, expected_data).await;
}

async fn test_recv(client: &mut AdnlReceiver, encrypted_packet: Vec<u8>, expected_data: Vec<u8>) {
    let mut data = Vec::<u8>::new();
    let mut binding = encrypted_packet.as_slice();
    let _r = client.receive::<_, _, 8192>(&mut binding, &mut data).await;
    assert_eq!(data, expected_data.as_slice(), "incoming packet is wrong");
}
