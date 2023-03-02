# 📦 Wasm-bpf: 为在 WebAssembly 上运行 eBPF 应用而设计的库、工具链和运行时

[![Actions Status](https://github.com/eunomia-bpf/wasm-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/wasm-bpf/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf)
[![DeepSource](https://deepsource.io/gh/eunomia-bpf/wasm-bpf.svg/?label=active+issues&show_trend=true&token=rcSI3J1-gpwLIgZWtKZC-N6C)](https://deepsource.io/gh/eunomia-bpf/wasm-bpf/?ref=repository-badge)

[中文文档](README_zh.md) [Gitee](https://gitee.com/eunomia-bpf/wasm-bpf) [Github](https://github.com/eunomia-bpf/wasm-bpf)

Wasm-bpf 是一个由 [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(一次编写 – 到处运行) [libbpf](https://github.com/libbpf/libbpf) libbpf 驱动的 WebAssembly eBPF 库、工具链和运行时。它可以帮助您几乎不用修改地构建几乎所有的 eBPF 程序或用例到 Wasm 中，并在 Wasm 沙箱中跨平台运行。

## 简介

`WebAssembly`（简称Wasm）是一种可执行代码的便携式二进制格式。代码在一个内存安全的沙盒环境中以接近本机速度执行，具有明确定义的资源限制和一个 API ，用于与嵌入式主机环境（例如代理）进行通信。

`wasm-bpf` 项目结合了 Wasm 和 eBPF 技术，提高了eBPF应用程序的性能和可编程性。它提供了一个库和工具链，用于将多种语言编写的 eBPF 应用编译成 Wasm，并提供运行时环境以在安全的沙箱中运行这些程序。

使用 wasm-bpf，用户可以动态加载和安全地执行用户自定义或社区贡献的 Wasm-eBPF 代码作为插件，例如在他们的网络相关软件产品，或可观测性平台中。这其中 eBPF 使得数据收集高效可扩展，同时 Wasm 也允许对这些数据进行高级处理和分析。

此外，它使开发人员能够使用熟悉的语言，如 C/C ++，Rust，Go 和其他 30 多种能编译到 Wasm 的编程语言编写 eBPF 程序，并轻松地在不同的Linux发行版中部署它们。此外，利用 Wasm 的生态和工具链，云提供商可以利用 wasm-bpf 为其客户提供安全且高性能的环境来开发和部署 eBPF 应用程序。

## 功能

- `通用性`: 提供了从 eBPF 到 Wasm 的大多数能力，包括从`环形缓冲区`或 `perf 缓冲区`进行轮询，使用 `maps` 在内核 eBPF 和用户空间 Wasm 之间进行双向通信，动态加载、挂载到 hook 执行等。支持大量的 eBPF 程序类型和 `maps` 类型。
- `高性能`: 对于复杂数据类型没有序列化开销，使用共享内存来避免主机和 Wasm 之间的拷贝开销。
- `易于使用`: 提供类似于 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) 的开发体验，自动生成 Wasm-eBPF 骨架头文件和类型定义以进行绑定。可以使用 `C/C++`、`Rust`、`Go` 编写 eBPF 程序并编译成 Wasm。
- `超轻量级`: 最小运行时的二进制大小仅为 1.5 MB。编译后的 Wasm 模块大小仅为 ~90K。使用相同的工具链，您可以轻松地在任何语言和平台上构建自己的 Wasm-eBPF 运行时！

请参阅 [examples](examples) 目录中以 C、Rust、Go 编写的编译为 Wasm 的 eBPF 程序示例，覆盖了从跟踪、网络到安全的各种用例。

有关使用 OCI 镜像分发、动态加载、运行 Wasm-eBPF 程序的工具，请参阅 [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) 仓库。

## 🔨 示例

请查看 [examples](examples) 目录中用 C、Rust、Go 编写的编译成 WASM 的 eBPF 程序示例。

`tracing examples`

- [bootstrap](examples/bootstrap) and [rust-bootstrap](examples/rust-bootstrap): 跟踪进程的 exec 和 exit 操作
- [runqlat](examples/runqlat): 将调度程序的运行队列延迟汇总成直方图
- [execve](examples/execve) and [go-execve](examples/go-execve): 跟踪 execve 系统调用

`security example`
- [lsm](examples/lsm) and  [go-lsm](examples/go-lsm): 检查删除目录的权限

`networking example`
- [sockfilter](examples/sockfilter): 监视数据包并处理 __sk_buff
- [sockops](examples/sockops): 在 syn 数据包中添加 pid 选项。

runqlat 的一个示例输出：

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

## 构建运行时

请参考 [docs/build.md](docs/build.md)。

## Wasm-bpf 工作原理

wasm-bpf 运行时需要两部分：主机端(在 Wasm 运行时之外)和 Wasm 客户端端(在 Wasm 运行时之内)。

- 主机端：一个简单的运行时实现示例
  - 参见 [runtime/cpp](runtime/cpp)，它将是在 [libbpf](https://github.com/libbpf/libbpf) 和 [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) 之上构建的 C++ 示例运行时。另一个更完善的基于 [Wasmtime](https://github.com/bytecodealliance/wasmtime) 的 Rust 运行时实现在 [runtime/rust](runtime/rust) 中。
  - 您可以使用相同的系统接口以 任何 语言、任何 eBPF 库和 任何 Wasm 运行时轻松构建自己的 Wasm-eBPF 运行时。
- wasm 端：工具链和库
  - 一个名为 [`libbpf-wasm`](wasm-sdk/c/libbpf-wasm.h) 的头文件库，为 Wasm 客户端 C/C++ 代码提供 libbpf API。
  - 一个名为 [`bpftool`](https://github.com/eunomia-bpf/bpftool/tree/wasm-bpftool) 的工具，用于生成 Wasm-eBPF skeleton 头文件和 C 结构定义，以便在主机和 Wasm 客户端之间传递数据而无需序列化。
  - 对于 Rust、Go 和其他语言的支持与 C/C++ 支持类似。

有关详细的编译过程，请参阅 [examples/bootstrap/README.md](examples/bootstrap/README.md)。下图显示了 eBPF 和 Wasm 运行时之间的整体交互过程：

![wasi-bpf](docs/wasm-bpf-no-bcc.png)

一个 Wasm 模块可以同时加载和控制多个 eBPF 程序，并且可以调用使用 组件模型 编写的其他语言编写的 Wasm 模块来处理数据或控制。

我们提出了一个新的 WASI 问题 wasi-bpf。

![wasi-bpf](docs/wasm-bpf-no-bcc.png)

Wasm 模块可以同时加载和控制多个 eBPF 程序， 并且能够调用或者控制（通过[组件模型](https://github.com/WebAssembly/component-model)）其他语言编写的 Wasm 模块来处理数据。

我们也提了一个 WASI 提案 [wasi-bpf](https://github.com/WebAssembly/WASI/issues/513)。

## 协议

MIT
