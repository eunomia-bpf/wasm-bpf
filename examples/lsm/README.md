# Demo BPF applications

## lsm-rmdir

`lsm-rmdir` hook in dir remove and check the permission to remove a directory. If dir
name with `can_not_rm` will raise Operation not permitted.

We can provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) development. Just run `make` to build the wasm binary:

```sh
make
```

Note: LSM may failed to load if the kernel is not configured as:

```sh
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_LSM=y
CONFIG_LSM="[other LSMs],bpf"
```

go wasm example(need tinygo):
```sh
make lsm_go_wasm # will output to go_wasm/lsm.go.wasm
```
