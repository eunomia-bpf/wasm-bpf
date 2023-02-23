# wasm-bpf: 超轻量级 eBPF 的 WASM 运行时

[![Actions Status](https://github.com/eunomia-bpf/wasm-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/wasm-bpf/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf)

一个 WebAssembly eBPF 库和运行时， 由 [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(一次编写 – 到处运行) [libbpf](https://github.com/libbpf/libbpf) 和 [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) 强力驱动。

- `通用`: 给 WASM 提供大部分的 eBPF 功能。 比如从 `ring buffer` 或者 `perf buffer` 中获取数据、 通过 `maps` 提供 `内核` eBPF 和 `用户态` Wasm 程序之间的双向通信、 动态 `加载`, `附加` 或者 `解除附加` eBPF程序等。 支持大量的 eBPF 程序类型和 map 类型， 覆盖了用于 `tracing（跟踪）`, `networking（网络）`, `security（安全）` 的使用场景。
- `高性能`: 对于复杂数据类型，没有额外的 `序列化` 开销。 通过 `共享内存` 来避免在 Host 和 WASM 端之间的额外数据拷贝。
- `简单便捷的开发体验`: 提供和 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) 相似的开发体验， `自动生成` Wasm-eBPF 的 `skeleton` 头文件以及用于绑定的 `类型` 定义。
- `非常轻量`: 运行时的示例实现只有 `300+` 行代码, 二进制文件只有 `1.5 MB` 的大小。 编译好的 WASM 模块只有 `~90K` 。你可以非常容易地使用任何语言，在任何平台上建立你自己的 Wasm-eBPF 运行时，使用相同的工具链来构建应用！

## 如何工作？

`wasm-bpf` 运行时需要两个部分: `主机侧`(Wasm 运行时之外) 以及 `Wasm 客户侧`(Wasm 运行时内)。

- host 侧: 见 [src](src) 以及 [include](include) 文件夹。 主机侧是一个构建在 [libbpf](https://github.com/libbpf/libbpf) 和 [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) 之上的运行时。
  - 使用同一套工具链，任何人用任何 wasm 运行时或者任何 ebpf 用户态库，以及任何语言，都可以在两三百行三四百行内轻松实现一套 wasm+ebpf 运行时平台，运行几乎所有的 ebpf 应用场景。
- wasm 侧:
  - 一个用于给 Wasm 客户侧 `C/C++` 代码提供 libbpf API的头文件库([`libbpf-wasm`](wasm-sdk/libbpf-wasm.h))。
  - 一个用来生成 Wasm-eBPF `skeleton` 头文件以及生成用于在主机侧和 Wasm 客户侧传递数据的 C 结构体定义的 [`bpftool`](https://github.com/eunomia-bpf/bpftool/tree/wasm-bpftool)。
  - 更多编程语言支持(比如 `Rust`、 `Go` 等)还在开发中。

对于更详细的编译过程, 请查阅 [examples/bootstrap/README.md](examples/bootstrap/README.md)。

## 示例

请转到 [examples](examples) 文件夹去查看使用 C, Rust, Go 编写并编译到 Wasm 的 eBPF-Wasm 程序的示例。

- [bootstrap](examples/bootstrap) and [runqlat](examples/runqlat) `追踪`
- [lsm](examples/lsm) `安全`
- [sockfilter](examples/sockfilter) `网络`

## 构建运行时

依赖只有 git submodule 里面的 libbpf 和 wasm-micro-runtime

```sh
git submodule update --init --recursive
```

## 安装依赖

构建示例需要用到 `clang`, `libelf` 和 `zlib` 。包名在不同的发行版间可能不同。

在 Ubuntu/Debian, 需要:

```shell
apt install clang libelf1 libelf-dev zlib1g-dev
```

在 CentOS/Fedora, 需要:

```shell
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

运行 `make` 来构建这些示例。 构建结果会被放在 `build` 文件夹里。 构建运行时需要用到 `cmake`。

```sh
make build
```

可以查阅 [CI](.github/workflows/c-cpp.yml) 来详细了解如何编译运行这些示例。

## Wasm-bpf 总览

![wasi-bpf](test/asserts/wasm-bpf-no-bcc.png)

Wasm 模块可以同时加载和控制多个 eBPF 程序， 并且能够调用或者控制（通过[组件模型](https://github.com/WebAssembly/component-model)）其他语言编写的 Wasm 模块来处理数据。

我们也提了一个 WASI 提案 [wasi-bpf](https://github.com/WebAssembly/WASI/issues/513)。

## 协议

MIT
