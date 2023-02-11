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
  - 一个用于给 Wasm 客户侧 `C/C++` 代码提供 libbpf API的头文件库([`libbpf-wasm`](wasm-include/libbpf-wasm.h))。
  - 一个用来生成 Wasm-eBPF `skeleton` 头文件以及生成用于在主机侧和 Wasm 客户侧传递数据的 C 结构体定义的 [`bpftool`](https://github.com/eunomia-bpf/bpftool/tree/wasm-bpftool)。
  - 更多编程语言支持(比如 `Rust`、 `Go` 等)还在开发中。

对于更详细的编译过程, 请查阅 [examples/bootstrap/README.md](examples/bootstrap/README.md)。

## 示例

请转到 [examples](examples) 文件夹去查看使用 C, Rust 编写并编译到 Wasm 的 eBPF-Wasm 程序的示例。

- [bootstrap](examples/bootstrap) and [runqlat](examples/runqlat) `追踪`
- [lsm](examples/lsm) `安全`
- [sockfilter](examples/sockfilter) `网络`

### C 示例: Bootstrap

`bootstrap` 是个简单但很现实的 eBPF 程序的示例。 这个示例可以跟踪进程的启动 (更精确地来说，是 `exec()` 那些系统调用) 和退出，然后输出进程的文件名、PID、父进程PID之类的数据，以及进程的退出状态和存活时间。使用 `-d <最小周期（毫秒>` 来限制要输出的进程的最小存活时间。 在这种模式下，进程启动事件不会被输出（科学一点，`exec()`，具体见下面的示例）。

`bootstrap` 是使用和来自 BCC 里的
[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) 类似的思路来开发的。 但是为了让用户的修改容易一些， `bootstrap` 更独立，并且使用了更简单的 Makefile 。 `bootstrap` 演示了典型的 eBPF 用途:

- 多个 BPF 程序协同工作 (在这里是进程 `exec（启动）` 和 `exit（退出）` 的事件处理函数)；
- 用 BPF map 来维护状态；
- 用 BPF 环形缓冲区来向用户态发送数据；
- 使用全局变量来修改程序行为。
- `bootstrap` 使用了 BPF 的 CO-RE 特性以及 `vmlinux.h` 来从内核的 `struct task_struct` 来读取额外的进程信息。

来看一个样例输出:

```console
$ sudo sudo ./wasm-bpf bootstrap.wasm -h
BPF bootstrap demo application.

It traces process start and exits and shows associated 
information (filename, process duration, PID and PPID, etc).

USAGE: ./bootstrap [-d <min-duration-ms>] -v
$ sudo ./wasm-bpf bootstrap.wasm
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
18:57:58 EXEC  sed              74911   74910   /usr/bin/sed
18:57:58 EXIT  sed              74911   74910   [0] (2ms)
18:57:58 EXIT  cat              74912   74910   [0] (0ms)
18:57:58 EXEC  cat              74913   74910   /usr/bin/cat
18:57:59 EXIT  cat              74913   74910   [0] (0ms)
18:57:59 EXEC  cat              74914   74910   /usr/bin/cat
18:57:59 EXIT  cat              74914   74910   [0] (0ms)
18:57:59 EXEC  cat              74915   74910   /usr/bin/cat
18:57:59 EXIT  cat              74915   74910   [0] (1ms)
18:57:59 EXEC  sleep            74916   74910   /usr/bin/sleep
```

原始的 C 代码来自 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)。

### Rust 示例: [Bootstrap](examples/rust-bootstrap)

类似 C bootstrap, 但是是 Rust 写的。

See [examples/rust-bootstrap](examples/rust-bootstrap) for more details.


### C 示例: runqlat

这个程序通过直方图展示调度器运行队列延迟，给我们展现了任务等了多久才能轮到 CPU 用。

```console
$ sudo ./wasm-bpf runqlat.wasm -h
Summarize run queue (scheduler) latency as a histogram.

USAGE: runqlat [--help] [interval] [count]

EXAMPLES:
    runqlat 1 10    # print 1 second summaries, 10 times
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

`runqlat` 也是个简单但有实际意义的 BPF 程序的例子。这个例子稍微复杂一些，它有超过一个文件，并且能直接读内核 map 而不是从内核的环形缓冲区获取数据。

运行时将会使用共享内存来访问内核 map，同时内核将会更新在共享内存中的 map ，所以 wasm 代码可以直接访问 eBPF map，而不需要面对用户态主机侧程序和 Wasm 运行时之间的额外拷贝开销。

可以使用 `bpf_map_update_elem` 在用户态程序内更新内核的 eBPF map，比如:

```c
        cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
        ....
        bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY);
```

所以内核的 eBPF 程序可以从 Wasm 侧的程序获取配置，或者在运行的时候接收消息。

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
