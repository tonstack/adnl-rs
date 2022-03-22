# ADNL

> :warning: **WARNING:** the library is not ready for production yet, public API is a subject to change.

Minimal ADNL implementation in Rust (client-server only, without p2p for now).

##  Roadmap

- [ ] Clarify where to use Montgomery and where -- compressed Edwards (curve25519)
- [ ] API docs & examples
- [ ] Extract JS examples from JS library
- [ ] Write ADNL specification to [ton-docs](https://github.com/tonstack/ton-docs)
- [ ] Implement server side & p2p protocol
- [ ] Implement high-level JS library on top of raw bindings
- [ ] Add benchmarks
- [ ] Publish package to crates.io and npmjs.com

## WASM Quickstart
```bash
cd wasm-bindings
npm i
npm run serve
```