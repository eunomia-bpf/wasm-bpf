# Runtime implementation

This directory contains two runtime implementations that can be used to execute eBPF user programs in WASM module format. 

- [cpp](./cpp): A runtime implemented in `C++`, using [wasm-micro-runtime](https://github.com/bytecodealliance/wasm-micro-runtime) as backend
- [rust](./rust): A runtime implemented in `Rust`, using [wasmtime](https://github.com/bytecodealliance/wasmtime) as beckend. Currently only this one supports running wasm modules geneated by `tinygo`