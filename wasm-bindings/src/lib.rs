#![no_std]

extern crate alloc;

use ciborium_io::{Read, Write};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use adnl::{AdnlAddress, AdnlAesParams, AdnlBuilder, AdnlClient, AdnlPublicKey, AdnlSecret};
use alloc::vec::Vec;

#[wasm_bindgen]
#[derive(Debug)]
pub struct JsTransport {
    read_exact: Function,
    write_all: Function,
    flush: Function,
}

#[wasm_bindgen]
impl JsTransport {
    #[wasm_bindgen(constructor)]
    pub fn new(read_exact: Function, write_all: Function, flush: Function) -> Self {
        Self {
            read_exact,
            write_all,
            flush,
        }
    }
}

impl Read for JsTransport {
    type Error = JsValue;

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        let result = self.read_exact.call1(&JsValue::null(), &JsValue::from(data.len()))?;
        let result = Uint8Array::from(result);
        result.copy_to(data);
        Ok(())
    }
}

impl Write for JsTransport {
    type Error = JsValue;

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.write_all.call1(&JsValue::null(), &Uint8Array::from(data))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.flush.call0(&JsValue::null())?;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct Client {
    client: AdnlClient<JsTransport>,
}

#[wasm_bindgen]
impl Client {
    #[wasm_bindgen(constructor)]
    pub fn new(receiver_pub_js: Uint8Array, sender_pub_js: Uint8Array, secret_js: Uint8Array, aes_params_js: Uint8Array, transport: JsTransport) -> Result<Client, JsValue> {
        let mut aes_params = [0u8; 160];
        let mut receiver_pub = [0u8; 32];
        let mut sender_pub = [0u8; 32];
        let mut secret = [0u8; 32];
        aes_params_js.copy_to(&mut aes_params);
        receiver_pub_js.copy_to(&mut receiver_pub);
        sender_pub_js.copy_to(&mut sender_pub);
        secret_js.copy_to(&mut secret);
        let aes_params = AdnlAesParams::from(aes_params);
        let receiver_addr: AdnlAddress = AdnlPublicKey::from(receiver_pub).into();
        let sender_pub = AdnlPublicKey::from(sender_pub);
        let secret = AdnlSecret::from(secret);
        let client = AdnlBuilder::with_static_aes_params(aes_params)
            .use_static_ecdh(sender_pub, receiver_addr, secret)
            .perform_handshake(transport)
            .map_err(|e| alloc::format!("{:?}", e))?;
        Ok(Self { client })
    }

    #[wasm_bindgen]
    pub fn send(&mut self, buffer: Uint8Array, nonce: Uint8Array) -> Result<(), JsValue> {
        let mut nonce: [u8; 32] = nonce.to_vec().try_into().map_err(|e| alloc::format!("{:?}", e))?;
        self.client.send(&mut buffer.to_vec(), &mut nonce).map_err(|e| alloc::format!("{:?}", e))?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn receive(&mut self) -> Result<Uint8Array, JsValue> {
        let mut result = Vec::<u8>::new();
        self.client.receive::<_, 8192>(&mut result).map_err(|e| alloc::format!("{:?}", e))?;
        Ok(Uint8Array::from(result.as_slice()))
    }
}

