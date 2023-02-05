# 示例 BPF 程序

## runqlat

Linux eBPF/bcc 版本的 runqlat 的演示。

这个程序通过直方图展示调度器运行队列延迟，给我们展现了任务等了多久才能轮到 CPU 用。

```console
$ sudo ./wasm-bpf runqlat.wasm -h
Summarize run queue (scheduler) latency as a histogram.

USAGE: runqlat [--help] [interval] [count]

EXAMPLES:
    runqlat         # summarize run queue latency as a histogram
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

图形显示的分布有两个峰，一个峰在 0 到 15 微秒间，另一个峰在 16 到 65 微秒。 这些分布可以从字符画统计图中的尖峰来观察到（其实只是 `数量` 这个值的可视化表现）。

再比如看一看 16384 微秒到 32767 微秒那一行，那一行有 809 个事件。

`runqlat` 也是个简单但有实际意义的 BPF 程序的例子。不过它稍微复杂一些，有超过一个文件，并且直接读内核 map 而不是从内核的环形缓冲区获取数据。

## runqlat.wasm 的编译过程

我们提供了与 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) 类似的开发体验。 只需要运行 `make` 就能构建 wasm 程序:

```sh
make
```

对于构建过程的具体描述，以及一些可能遇到的问题，请查阅 [bootstrap/README.md](../bootstrap/README.md)。

## `maps` API

可以使用 `map` API 来从用户态访问内核里的 `map`，例如：

```c
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &hist);
        ...
        lookup_key = next_key;
    }
    lookup_key = -2;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        ...
        lookup_key = next_key;
    }
```

运行时将会使用共享内存来访问内核 map，同时内核将会更新在共享内存中的 map ，所以 wasm 代码可以直接访问 eBPF map，而不需要面对用户态主机侧程序和 Wasm 运行时之间的额外拷贝开销。

可以使用 `bpf_map_update_elem` 在用户态程序内更新内核的 eBPF map，比如:

```c
        cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
        cgfd = open(env.cgroupspath, O_RDONLY);
        if (cgfd < 0) {
            ...
        }
        if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
            ...
        }
```

所以内核的 eBPF 程序可以从 Wasm 侧的程序获取配置，或者在运行的时候接收消息。
