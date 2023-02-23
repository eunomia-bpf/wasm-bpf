# Examples

There are examples using wasm-bpf.

Each directory contains one example. 
- `go-**` stands for examples that userpsace program was written in Go. 
- `rust-**` denotes that the userspace program is written in Rust. 
- Others means that the userspace program is written in `C/C++`

Go examples requires `tinygo`, rust examples requires `cargo`.

### C example: [Bootstrap](examples/bootstrap)

`bootstrap` is an example of a simple (but realistic) BPF application. It
tracks process starts (`exec()` family of syscalls, to be precise) and exits
and emits data about filename, PID and parent PID, as well as exit status and
duration of the process life. With `-d <min-duration-ms>` you can specify
minimum duration of the process to log. In such mode process start
(technically, `exec()`) events are not output (see example output below).

`bootstrap` was created in the similar spirit as
[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) from
BCC package, but is designed to be more stand-alone and with simpler Makefile
to simplify adoption to user's particular needs. It demonstrates the use of
typical BPF features:

- cooperating BPF programs (tracepoint handlers for process `exec` and `exit`
    events, in this particular case);
- BPF map for maintaining the state;
- BPF ring buffer for sending data to user-space;
- global variables for application behavior parameterization.
- it utilizes BPF CO-RE and vmlinux.h to read extra process information from
    kernel's `struct task_struct`.

Here's an example output:

```console
$ sudo ./wasm-bpf bootstrap.wasm -h
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

See [examples/bootstrap](examples/bootstrap) for more details.

### Rust example: [Bootstrap](examples/rust-bootstrap)

similar to C bootstrap, but written in Rust.

See [examples/rust-bootstrap](examples/rust-bootstrap) for more details.

### C example: [runqlat](examples/runqlat)

This program summarizes scheduler run queue latency as a histogram, showing
how long tasks spent waiting their turn to run on-CPU.

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

`runqlat` is also an example of a simple (but realistic) BPF application. It
would show a more complex example of BPF program, which contains more than
one file, and directly access the kernel maps from the user space instead of
polling the kernel ring buffer.

The runtime would use shared memory to access the kernel maps, and the kernel
would update the maps in the shared memory, so the wasm code can access the
eBPF maps directly, without any serialization or copy overhead between userspace
host and Wasm runtime.

You can use the `bpf_map_update_elem` API to update the kernel maps from the user
space, for example:

```c
        cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
        ....
        bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY);
```

So the kernel eBPF can be config by wasm side or recieve the messages from
userspace wasm runtime when it is running.

See [examples/runqlat](examples/runqlat) for more details.

### C example: lsm-rmdir

`lsm-rmdir` hook in dir remove and check the permission to remove a directory. If dir
name with `can_not_rm` will raise Operation not permitted.

See [examples/lsm](examples/lsm) for more details.

### C example: Socket filter

sockfilter is an example of monitoring packet and dealing with __sk_buff structure.

See [examples/sockfilter](examples/sockfilter) for more details.

### C example: Sockops

`sockops` add the pid int tcp option in syn packet.

See [examples/sockops](examples/sockops) for more details.
