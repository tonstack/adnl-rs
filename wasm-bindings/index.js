import { Client, JsTransport } from './pkg';

function read_exact(len) {
    console.log("read " + len + " bytes");
    return new Uint8Array(len);
}

function write_all(data) {
    console.log(data);
}

function flush() {

}

function _base64ToUint8Array(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

let transport = new JsTransport(read_exact, write_all, flush);

let receiver_pub = _base64ToUint8Array("JhXt7H1dZTgxQTIyGiYV4f9VUARuDxFl/1kVBjLSMB8=");
let sender_pub = _base64ToUint8Array("UDRyFtQ6suh/QUarqr0uAeWapuSbpRdDBKld9yOfAbE=");
let secret = _base64ToUint8Array("293A2VeFAyl2b9jpo3ChFdIpYlAT6lhJkAwGP53G7Gs=");
let aes_params = new Uint8Array(160);
window.crypto.getRandomValues(aes_params);

let client = new Client(receiver_pub, sender_pub, secret, aes_params, transport);

let buffer = _base64ToUint8Array("evmLtDUmPmyV1v7LSX39CqXwMefUEphrXOcgSW21EgUujy0QDN8GjHkENFqtFgAAAAAAAA==");
let nonce = new Uint8Array(32);
window.crypto.getRandomValues(nonce);
client.send(buffer, nonce);
console.log(client.receive());