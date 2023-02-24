![logo](docs/logo.png)

# 📦 Wasm-bpf: Wasm library and toolchain for eBPF

[![Actions Status](https://github.com/eunomia-bpf/wasm-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/wasm-bpf/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf)
[![DeepSource](https://deepsource.io/gh/eunomia-bpf/wasm-bpf.svg/?label=active+issues&show_trend=true&token=rcSI3J1-gpwLIgZWtKZC-N6C)](https://deepsource.io/gh/eunomia-bpf/wasm-bpf/?ref=repository-badge)

[中文文档](README_zh.md)

`Wasm-bpf` is a WebAssembly eBPF library, toolchain and runtime powered by [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(Compile Once – Run Everywhere) [libbpf](https://github.com/libbpf/libbpf). It can help you build almost every eBPF programs or usecases to `Wasm` with nearly zero modification, and run them cross platforms with Wasm sandbox.

## Features

- **`General purpose`**: provide most abilities from eBPF to Wasm, `polling` from the ring buffer or perf buffer, bidirectional communications between `kernel` eBPF and `userspace` Wasm using `maps`, dynamically `loading`, `attaching` or `detaching`, etc. Supports a large number of eBPF program types and map types.
- **`High performance`**: No `serialization` overhead for complex data types, using `shared memory` to avoid copy overhead between host and Wasm.
- **`Easy to use`**: provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), `auto generate` the Wasm-eBPF skeleton headers and type definitions for bindings. Write your eBPF programs in `C/C++`, `Rust`, `Go` and compile to Wasm.
- **`Ultralightweight`**: the miminal runtime has only `1.5 MB` in binary size. Compiled Wasm module would be only `~90K`. With the same toolchain, you can easily build your own Wasm-eBPF runtime in any languages and platforms!

See the [examples](examples) directory for examples of eBPF programs written in C, Rust, Go and compiled to Wasm, covering the use cases from `tracing`, `networking` to `security`.

For tools to distribute Wasm-eBPF programs in [`OCI`](https://opencontainers.org/) images, please refer to [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) repo.

## 🔨 Examples

See the [examples](examples) directory for examples of eBPF programs written in C, Rust, Go and compiled to WASM.

`tracing examples`

- [bootstrap](examples/bootstrap) and [rust-bootstrap](examples/rust-bootstrap): trace process exec and exit
- [runqlat](examples/runqlat): summarizes scheduler run queue latency as a histogram
- [execve](examples/execve) and [go-execve](examples/go-execve): trace execve syscall

`security example`
- [lsm](examples/lsm) and  [go-lsm](examples/go-lsm): check the permission to remove a directory

`networking example`
- [sockfilter](examples/sockfilter): monitoring packet and dealing with __sk_buff.
- [sockops](examples/sockops): Add the pid int tcp option in syn packet.

An example output of runqlat:

```console
$ sudo ./wasm-bpf runqlat.wasm 1
Tracing run queue latency... Hit Ctrl-C to end.

     usecs               : count    distribution
         0 -> 1          : 72       |*****************************           |
         2 -> 3          : 93       |*************************************   |
         4 -> 7          : 98       |****************************************|
         8 -> 15         : 96       |*************************************** |
        16 -> 31         : 38       |***************                         |
        32 -> 63         : 4        |*                                       |
        64 -> 127        : 5        |**                                      |
       128 -> 255        : 6        |**                                      |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 1        |                                        |
```

## How it works

The wasm-bpf runtime require two parts: `the host side`(Outside the Wasm runtime) and the `Wasm guest side`(Inside the Wasm runtime).

- host side: A simple runtime implementation example
  - see [runtime/cpp](runtime/cpp), which would be a sample runtime in `C++` built on the top of [libbpf](https://github.com/libbpf/libbpf) and [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime). Another more complex runtime implement in `Rust` is [runtime/rust](runtime/rust), based on [Wasmtime](https://github.com/bytecodealliance/wasmtime).
  - You can easily build your own Wasm-eBPF runtime in `any` languages, `any` eBPF libraries and `any` Wasm runtimes with the same System interface.
- wasm side: toolchains and libraries
  - a [`libbpf-wasm`](wasm-sdk/c/libbpf-wasm.h) header only library to provide libbpf APIs for Wasm guest `C/C++` code.
  - a [`bpftool`](https://github.com/eunomia-bpf/bpftool/tree/wasm-bpftool) tool to generate the Wasm-eBPF `skeleton` headers, and `C struct definitions` for passing data between the host and Wasm guest without serialization.
  - `Rust`, `Go` and other language support is similar to the `C/C++` support.

For details compile process, please refer to the [examples/bootstrap/README.md](examples/bootstrap/README.md).  The figure below shows the overall interaction between the eBPF and Wasm runtimes:

![wasi-bpf](docs/wasm-bpf-no-bcc.png)

A Wasm module could load and control multiple eBPF programs at the same time, and can call another Wasm module written in other languages to process the data or control with [the component model](https://github.com/WebAssembly/component-model).

We have proposed a new WASI issue [wasi-bpf](https://github.com/WebAssembly/WASI/issues/513).

## Build the runtime

We have two types of runtime samples:

- A C/C++ runtime example, which is a minimal runtime based on WAMR. see [runtime/cpp](../runtime/cpp) for more details.
- A Rust runtime example, which is a more complex runtime based on Wasmtime. see [runtime/rust](../runtime/rust) for more details.

The runtime can be built as a library or a standalone executable. see [docs/build.md](docs/build.md) to build the runtimes.

## LICENSE

[MIT LICENSE](LICENSE)

## 🔗 Links

- eunomia-bpf project: simplify and enhance eBPF with CO-RE and WebAssembly https://github.com/eunomia-bpf/eunomia-bpf
- documents and blogs: https://eunomia-bpf.github.io/blog/ebpf-wasm.html
- CO-RE (Compile Once – Run Everywhere): https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
- WAMR (WebAssembly Micro Runtime): https://github.com/bytecodealliance/wasm-micro-runtime
- libbpf: https://github.com/libbpf/libbpf
