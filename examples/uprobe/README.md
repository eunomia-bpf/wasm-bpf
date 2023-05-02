# Demo BPF applications

## uprobe

`uprobe` can be attached to certain functions of specified process.

First we need to compile and run the target program:

```console
# clang target.c -o target
# ./target
```

Now we can try to trace function calls of the target process by

```console
# make
# ../wasm-bpf uprobe.wasm
```

After that we can see it's output by:

```console
# cat /sys/kernel/debug/tracing/trace_pipe
```

It will look like:

```console
          target-217543  [000] d...1 759561.724568: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759561.724574: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759563.724751: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759563.724756: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759565.724898: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759565.724902: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759567.725020: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-217543  [000] d...1 759567.725024: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
```

> In the example of libbpf-bootstrap(https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/uprobe.bpf.c), the BPF code use `SEC("uprobe//proc/self/exe:uprobed_sub")` to attach to the process of itself. This won't work in wasm-bpf because you program will be compiled to WASM and be executed by wasm runtime rather than the machine, so kernel can't see your code of userpace directly.