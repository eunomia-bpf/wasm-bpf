# Demo BPF applications

## runqlat

Demonstrations of runqlat, the Linux eBPF/bcc version.

This program summarizes scheduler run queue latency as a histogram, showing
how long tasks spent waiting their turn to run on-CPU.

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

The distribution is bimodal, with one mode between 0 and 15 microseconds,
and another between 16 and 65 milliseconds. These modes are visible as the
spikes in the ASCII distribution (which is merely a visual representation
of the "count" column). As an example of reading one line: 809 events fell
into the 16384 to 32767 microsecond range (16 to 32 ms) while tracing.

`runqlat` is alse an example of a simple (but realistic) BPF application. It
would show a more complex example of BPF program, which contains more than
one file, and directly access the kernel maps from the user space instead of
polling the kernel ring buffer.

## the compile process of the runqlat.wasm

We can provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) development. Just run `make` to build the wasm binary:

```sh
make
```

For the description of the build process and the issues may occured, please refer to the [bootstrap/README.md](../bootstrap/README.md).

## The maps API

You can use the map API to access the kernel maps from the user space, for example:

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

The runtime would use shared memory to access the kernel maps, and the kernel would update the maps in the shared memory, so the wasm code can access the maps directly, without any serialization or copy overhead between host and Wasm runtime.

You can use the `bpf_map_update_elem` API to update the kernel maps from the user space, for example:

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

So the kernel eBPF can be config by wasm side or recieve the messages from userspace wasm runtime when it is running.
