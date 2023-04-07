# Demo BPF applications

## xdp

`xdp` just print the size of every packet it receives and then let them pass.

The original c code of kernel side is from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap).

We can provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) development. Just run `make` to build the wasm binary:

```sh
make
```

You can attach the xdp program to certain network interface by:

```sh
../wasm-bpf xdp.wasm device_name
```

For example `../wasm-bpf ./xdp.wasm enp1s0`.

After that you can see it's output by:

```sh
cat /sys/kernel/debug/tracing/trace_pipe
```

It will look like:

```
          <idle>-0       [000] d.s.. 89309.534085: bpf_trace_printk: packet size: 66

          <idle>-0       [000] d.s.. 89309.595121: bpf_trace_printk: packet size: 66

          <idle>-0       [000] d.s.. 89309.686768: bpf_trace_printk: packet size: 126

          <idle>-0       [000] d.s.. 89309.689973: bpf_trace_printk: packet size: 66

          <idle>-0       [000] d.s.. 89309.836179: bpf_trace_printk: packet size: 54
```