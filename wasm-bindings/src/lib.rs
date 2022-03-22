#![no_std]

use ciborium_io::{Read, Write};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use adnl::{AdnlAddress, AdnlAesParams, AdnlBuilder, AdnlPublicKey, AdnlSecret};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert(&"Hello!");
}

#[wasm_bindgen]
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
    type Error = ();

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact.call1(&JsValue::null(), &JsValue::from(data.len()));
        Ok(())
    }
}

impl Write for JsTransport {
    type Error = ();

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}

#[wasm_bindgen]
pub fn new_client(receiver_addr_js: Uint8Array, sender_pub_js: Uint8Array, secret_js: Uint8Array, aes_params_js: Uint8Array, transport: JsTransport) {
    let mut aes_params = [0u8; 160];
    let mut receiver_addr = [0u8; 32];
    let mut sender_pub = [0u8; 32];
    let mut secret = [0u8; 32];
    aes_params_js.copy_to(&mut aes_params);
    receiver_addr_js.copy_to(&mut receiver_addr);
    sender_pub_js.copy_to(&mut sender_pub);
    secret_js.copy_to(&mut secret);
    let aes_params = AdnlAesParams::from(aes_params);
    let receiver_addr: AdnlAddress = AdnlPublicKey::from(receiver_addr).into();
    let sender_pub = AdnlPublicKey::from(sender_pub);
    let secret = AdnlSecret::from(secret);
    let client = AdnlBuilder::with_static_aes_params(aes_params)
        .use_static_ecdh(sender_pub, receiver_addr, secret)
        .perform_handshake(transport);
}