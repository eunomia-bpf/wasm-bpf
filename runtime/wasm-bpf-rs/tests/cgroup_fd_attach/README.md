# Test program for attaching by file descriptor

This wasm program attaches the `sockops` program from `examples/sockops` to the cgroup the
runtime preopened for it, passing `wasm_attach_bpf_program_fd` the descriptor it was handed
rather than a path. It then checks that a descriptor it was never given and a descriptor that
is open but is not a preopened directory are both refused. A directory the guest opens for
itself cannot be checked here: under a rights-free preopen the guest cannot open a directory at
all, and that refusal is covered by the unit tests in `src/tests/fd.rs`.

The Rust side is `test_attach_cgroup_by_fd`, which preopens `/sys/fs/cgroup` at `/guestmnt`. It
is `#[ignore]`d, since attaching a `sockops` program needs kernel support that CI does not have,
so run it with `cargo test -- --ignored test_attach_cgroup_by_fd` as root on a machine that does.

Building needs wasi-sdk in `/opt/wasi-sdk`, and a kernel with BTF for the `.bpf.o`:

```console
$ make
```
