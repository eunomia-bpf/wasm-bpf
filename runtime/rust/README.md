# wasm-bpf-rs

A rust WebAssembly-eBPF runtime for wasm-bpf project based on libbpf and [wasmtime](https://wasmtime.dev/).

**Not finished yet! DO NOT USE IT DIRECTLY!**

## 📦 [Wasm-bpf: Wasm library and toolchain for eBPF](https://github.com/eunomia-bpf/wasm-bpf)

[`Wasm-bpf`](https://github.com/eunomia-bpf/wasm-bpf) is a WebAssembly eBPF library, toolchain and runtime powered by [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(Compile Once – Run Everywhere) [libbpf](https://github.com/libbpf/libbpf). It can help you build almost every eBPF programs or usecases to `Wasm`.

### Features

- **`General purpose`**: provide most abilities from eBPF to Wasm, `polling` from the ring buffer or perf buffer, bidirectional communications between `kernel` eBPF and `userspace` Wasm using `maps`, dynamically `loading`, `attaching` or `detaching`, etc. Supports a large number of eBPF program types and map types.
- **`High performance`**: No `serialization` overhead for complex data types, using `shared memory` to avoid copy overhead between host and Wasm.
- **`Easy to use`**: provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), `auto generate` the Wasm-eBPF skeleton headers and type definitions for bindings.
- **`Ultralightweight`**: the sample runtime has only `1.5 MB` in binary size. Compiled Wasm module would be only `~90K`. With the same toolchain, you can easily build your own Wasm-eBPF runtime in any languages and platforms!

See the [examples](examples) directory for examples of eBPF programs written in C, Rust and compiled to Wasm, covering the use cases from `tracing`, `networking` to `security`.

For tools to distribute Wasm-eBPF programs in [`OCI`](https://opencontainers.org/) images, please refer to [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) repo.

### 🔗 Links

- wasm-bpf GitHub Repository: https://github.com/eunomia-bpf/wasm-bpf
- eunomia-bpf project: simplify and enhance eBPF with CO-RE and WebAssembly https://github.com/eunomia-bpf/eunomia-bpf
- documents and blogs: https://eunomia-bpf.github.io/blog/ebpf-wasm.html
- CO-RE (Compile Once – Run Everywhere): https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
- WAMR (WebAssembly Micro Runtime): https://github.com/bytecodealliance/wasm-micro-runtime
- wasmtime: https://wasmtime.dev/
- libbpf: https://github.com/libbpf/libbpf
