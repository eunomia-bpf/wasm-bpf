# BPF应用程序

## Bootstrap

`bootstrap`是一个简单（但实用）的BPF应用程序的例子。它跟踪进程的启动（准确地说，是 `exec() `系列的系统调用）和退出并发送关于文件名、PID和父PID的数据，以及退出状态和
进程的持续时间。用`-d <min-duration-ms>`你可以指定要记录的进程的最小持续时间。在这种模式下，进程启动(技术上来说，`exec()`)事件不会被输出（见下面的例子）。

`bootstrap`是根据BCC软件包中的[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools)的类似思想创建的，但它被设计成更独立的，并且有更简单的Makefile以简化用户的特殊需求。它演示了典型的BPF特性：

- 合作BPF程序（在这种特殊情况下，是进程`exec`和`exit`的跟踪点处理程序）；
- 维护状态的BPF map ；
- 将数据发送到用户空间的BPF ring buffer；
- 用于应用程序行为参数化的全局变量。
- 它利用BPF CO-RE和vmlinux.h从内核的`struct task_struct`中读取额外的进程信息。

Bootstrap 旨在为你的 BPF 应用程序提供起点，其中包括 BPF CO-RE 和 vmlinux.h，BPF ring buffer的数据的消费，命令行参数的解析，优雅的 Ctrl-C 处理等关键但却乏味的任务，这些任务是必须的，但对于任何有用的事情来说是乏味的。只需复制/粘贴并进行简单的重命名即可开始使用。

以下是一个输出示例：

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

原始代码来自[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)。

## bootstrap.wasm 编译过程

我们可以提供与 libbpf-bootstrap 开发相似的开发体验。只需运行 make 即可构建 wasm 二进制文件：

```console
make
```

这将触发以下步骤：

+ 使用clang和llvm-strip构建BPF程序，以剥离调试信息：

  ```console
  clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../../third_party/vmlinux/x86/ -idirafter /usr/lib/llvm-15/lib/clang/15.0.2/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -c bootstrap.bpf.c -o bootstrap.bpf.o
  
  ```

  BPF程序的内核部分与libbpf完全相同（或者可以使用clang编译的任何其他风格）。一旦完成了 [bcc to libbpf converter](https://github.com/iovisor/bcc/issues/4404)，就可以以这种方式编译BCC风格。

+ 从BPF程序生成C头文件：

  ```console
  ../../third_party/bpftool/src/bpftool gen skeleton -j bootstrap.bpf.o > bootstrap.skel.h
  ```

  C skel包含一个 BPF 程序的skeleton，用于操作 BPF 对象，并控制 BPF 程序的生命周期，例如：

    ```c
    struct bootstrap_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
            struct bpf_map *exec_start;
            struct bpf_map *rb;
            struct bpf_map *rodata;
        } maps;
        struct {
            struct bpf_program *handle_exec;
            struct bpf_program *handle_exit;
        } progs;
        struct bootstrap_bpf__rodata {
            unsigned long long min_duration_ns;
        } *rodata;
        struct bootstrap_bpf__bss {
            uint64_t /* pointer */ name_ptr;
        } *bss;
    };
    ```
  因为主机（或 eBPF 侧）的结构体布局可能与目标（Wasm 侧）的结构体布局不同，所以所有指针都将根据主机的指针大小转换为整数。例如，`name_ptr` 是指向 `struct exec_start_`t 结构体中的 `name` 字段的指针。此外，填充字节将明确添加到结构体中以确保结构体布局与目标端相同，例如使用 `char __pad0[4];`。这是我们为 Wasm 修改的 `bpftool` 工具生成的。
  
+ 构建用户态的wasm代码

  ```sh
  /opt/wasi-sdk/bin/clang -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined -o bootstrap.wasm bootstrap.c
  ```

  需要wasi-sdk才能构建wasm二进制文件。您也可以使用emcc工具链来构建wasm二进制文件，命令应该是相似的。

  您可以运行以下命令来安装 wasi-sdk：

  ```sh
  wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sdk-17.0-linux.tar.gz
  tar -zxf wasi-sdk-17.0-linux.tar.gz
  sudo mkdir -p /opt/wasi-sdk/ && sudo mv wasi-sdk-17.0/* /opt/wasi-sdk/
  ```

  >由于宿主机（或 eBPF 端）的结构布局可能与目标（Wasm 端）的结构布局不同，因此需要注意用户空间代码之间的结构布局。您可以使用 ecc 和我们的 wasm-bpftool 生成用户空间代码的 C 头文件：
  >
  >```sh
  >ecc bootstrap.h --header-only
  > ../../third_party/bpftool/src/bpftool btf dump file bootstrap.bpf.o format c -j > bootstrap.wasm.h
  >```
  >
  >eunomia-bpf 中的`ecc`编译器将使用libclang和llvm查找头文件中的所有结构体定义，并自动向ebpf对象添加更多的btf信息。原始的`clang`可能并不总是能生成足够的btf信息来提供给wasm-bpf工具生成正确的C头文件。
  >
  >**注意：此过程和工具并不总是必需的，你可以手动完成。**你可以手动编写所有事件结构体定义，使用`__attribute__((packed))`避免填充字节，并在主机和wasm端之间转换所有指针为正确的整数。所有类型必须在wasm中定义与主机端相同的大小和布局。对于简单的事件这是很容易的，但对于复杂的程序却很难，因此我们创建了wasm特定的`bpftool`，用于从`BTF`信息中生成包含所有类型定义和正确结构体布局的C头文件，以便用户空间代码使用。
  >
  >我们创建了一个特殊的 POC 工具，它不属于 `bpftool`，可以生成 eBPF/主机端和 Wasm 之间的不需要序列化的 C 结构体绑定，您可以在 [c-struct-bindgen](https://github.com/eunomia-bpf/c-struct-bindgen) 中找到它。关于如何处理结构体布局问题的更多详细信息，可以在 c-struct-bindgen 工具的 README 中找到。

libbpf API 为 wasm 程序提供了一个仅包含头文件的库，您可以在 libbpf-wasm.h（wasm-include/libbpf-wasm.h）中找到它。wasm 程序可以使用 libbpf API 和 syscall 操作 BPF 对象，例如：

```c
/* Load and verify BPF application */
skel = bootstrap_bpf__open();
/* Parameterize BPF code with minimum duration parameter */
skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
/* Load & verify BPF programs */
err = bootstrap_bpf__load(skel);
/* Attach tracepoints */
err = bootstrap_bpf__attach(skel);
```

rodata 部分用于存储 BPF 程序中的全局变量，bss 部分用于存储用户空间代码中的全局变量，这些全局变量将在 bpftool gen skeleton time 映射到正确的偏移量，因此不需要在 Wasm 中编译 libelf 库，运行时仍可动态加载和操作 BPF 对象。

Wasm 端的 C 代码与本地 libbpf 代码略有不同，但它可以从 eBPF 端提供大部分功能，例如，从环形缓冲区或 perf 缓冲区轮询，从 Wasm 端和 eBPF 端访问映射，加载、附加和分离 BPF 程序等。它可以支持大量的 eBPF 程序类型和映射，涵盖从跟踪、网络、安全等方面的大多数 eBPF 程序的使用场景。

由于wasm端缺少一些功能，例如信号处理程序还不支持（2023年2月），原始的C代码无法直接编译为wasm，您需要稍微修改代码以使其工作。我们将尽最大努力使wasm端的libbpf API与本机libbpf API尽可能相似，以便用户空间代码可以在未来直接编译为wasm。我们还将尽快提供更多语言绑定（Rust，Go等）的wasm端bpf API。

该轮询API将是环形缓冲区和性能缓冲区的一个封装，用户空间代码可以使用相同的API从环形缓冲区或性能缓冲区中轮询事件，具体取决于BPF程序中指定的类型。例如，环形缓冲区轮询定义为BPF_MAP_TYPE_RINGBUF的映射：

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

你可以使用以下代码从环形缓冲区轮询事件：

```c
rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
/* Process events */
printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
       "PPID", "FILENAME/EXIT CODE");
while (!exiting) {
    // poll buffer
    err = bpf_buffer__poll(rb, 100 /* timeout, ms */);
```



环形缓冲区轮询不需要序列化开销。bpf_buffer__poll API 将调用 handle_event 函数来处理环形缓冲区中的事件数据。

运行时基于 libbpf CO-RE（编译一次-随处运行）API，用于将 bpf 对象加载到内核中，因此 wasm-bpf 程序不受它编译的内核版本的影响，可以在任何支持 BPF CO-RE 的内核版本上运行。

bootstrap.wasm 的大小仅为 ~90K，很容易通过网络分发，并可以在不到 100ms 的时间内在另一台机器上动态部署、加载和运行。运行时不需要内核头文件、LLVM、clang 依赖关系，也不需要做重量级的编译工作！

如果想看更复杂的示例，可以在 examples 目录中找到 runqlat 程序。
