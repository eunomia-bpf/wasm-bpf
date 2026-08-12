# Test program for attaching by file descriptor

This wasm program attaches the `sockops` program from `examples/sockops` to the cgroup the
runtime preopened for it, passing `wasm_attach_bpf_program_fd` the descriptor it was handed
rather than a path. It then checks that a descriptor it was never given, a descriptor that is
open but is not a preopened directory, and a directory it opened for itself are all refused.

The Rust side is `test_attach_cgroup_by_fd`, which preopens `/sys/fs/cgroup` at `/guestmnt`. It
is `#[ignore]`d, since attaching a `sockops` program needs kernel support that CI does not have,
so run it with `cargo test -- --ignored test_attach_cgroup_by_fd` as root on a machine that does.

Building needs wasi-sdk in `/opt/wasi-sdk`, and a kernel with BTF for the `.bpf.o`:

```console
$ make
```
