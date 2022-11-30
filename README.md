# libbpf-wasm

libbpf-wasm is a library that allows you to compile and run libbpf eBPF programs in the WebAssembly virtual machine.

It should be used with [eunomia-bpf](https://https://github.com/eunomia-bpf/eunomia-bpf) library.

See the eunomia-bpf example code in [sigsnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/sigsnoop)

## Compile and Run

Use [sigsnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/sigsnoop) as an example. You need to clone the eunomia-bpf repo first.

Compile:

```shell
cd examples/bpftools/sigsnoop
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Or compile with `ecc`:

```console
$ cd examples/bpftools/sigsnoop
$ ecc sigsnoop.bpf.c sigsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Generate WASM skel:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest gen-wasm-skel
```

> The skel is generated and commit, so you don't need to generate it again.
> skel includes:
>
> - eunomia-include: include headers for WASM
> - app.c: the WASM app. all library is header only.

Build WASM module

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest build-wasm
```

Run:

```console
$ sudo ./ecli run app.wasm -h
Usage: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]
Trace standard and real-time signals.


    -h, --help  show this help message and exit
    -x, --failed  failed signals only
    -k, --killed  kill only
    -p, --pid=<int>  target pid
    -s, --signal=<int>  target signal

$ sudo ./ecli run app.wasm                                                                       
running and waiting for the ebpf events from perf event...
{"pid":185539,"tpid":185538,"sig":17,"ret":0,"comm":"cat","sig_name":"SIGCHLD"}
{"pid":185540,"tpid":185538,"sig":17,"ret":0,"comm":"grep","sig_name":"SIGCHLD"}

$ sudo ./ecli run app.wasm -p 1641
running and waiting for the ebpf events from perf event...
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
```

## License

MIT LICENSE
