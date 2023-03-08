# Runtime implementation example

We have three runtime implementations, based on WAMR, wasmtime, and WasmEdge.

This directory contains two runtime sample implementations that can be used to execute eBPF user programs in Wasm module format. 

- [cpp](./cpp): A runtime implemented in `C++`, using [wasm-micro-runtime](https://github.com/bytecodealliance/wasm-micro-runtime) as backend
- [rust](./rust): A runtime implemented in `Rust`, using [wasmtime](https://github.com/bytecodealliance/wasmtime) as runtime. Currently only this one supports running wasm modules geneated by `tinygo`

Wasmedge runtime plugin can be found in https://github.com/eunomia-bpf/WasmEdge/tree/master/plugins%2Fwasm-bpf
