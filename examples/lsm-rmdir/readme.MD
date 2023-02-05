# Demo BPF applications

## lsm-rmdir

`lsm-rmdir` is an example of a simple (but realistic) BPF application. It
hook in dir remove and check the permission to remove a directory. If dir 
name with `can_not_rm` will raise Operation not permitted

```bash
$ sudo ./wasm-bpf lsm.wasm
```