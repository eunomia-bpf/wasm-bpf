# Demo BPF applications

## uprobe

`uprobe` can be attached to certain function of specified process.

First we need to compile and run a target program:

```console
# clang target.c -o target
# ./target
```

Then we can find the pid of target process by `ps` command:

```console
# ps -aux | grep target
root      201957  0.0  0.1   2772  1048 pts/14   S+   05:14   0:00 ./target
root      202026  0.0  0.2   6476  2084 pts/33   S+   05:15   0:00 grep --color=auto target
```

and now we get the pid as `201957`.

Next we have to change the attach target in `uprobe.bpf.c`:

```C
SEC("uprobe//proc/pid/exe:uprobe_add")
int BPF_KPROBE(uprobe_add, int a, int b)
{
	bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);
	return 0;
}
```

We will change the `pid` to a real pid like:

```C
SEC("uprobe//proc/201957/exe:uprobe_add")
int BPF_KPROBE(uprobe_add, int a, int b)
{
	bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);
	return 0;
}
```

Now we can try to trace calls of the specified function in target process by

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
          target-204875  [000] d...1 682495.782361: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682495.782368: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682497.782564: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682497.782569: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682499.782720: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682499.782726: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682501.782882: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682501.782887: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682503.783065: bpf_trace_printk: uprobed_add ENTRY: a = 1, b = 1
          target-204875  [000] d...1 682503.783072: bpf_trace_printk: uprobed_sub ENTRY: a = 1, b = 1
```

> In the example of libbpf-bootstrap(https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/uprobe.bpf.c), the BPF code use `SEC("uprobe//proc/self/exe:uprobed_sub")` to attach to the process of itself. This won't work in wasm-bpf because you program will be compiled to WASM and be executed by wasm runtime rather than the machine, so kernel can't see your code of userpace.