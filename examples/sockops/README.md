# Demo BPF applications

## lsm-rmdir

`sockops` add the pid int tcp option in syn packet.

We can provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) development. Just run `make` to build the wasm binary:

```sh
make
```

test the prog load and attach correctly
```sh
bpftool prog list | grep -i pid_tcp_opt_inject -A 3 
```

open wireshark to capture and verify the tcp option(kind 254) is add to option in syn packet
