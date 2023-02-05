# Demo BPF applications

## lsm-rmdir

`lsm-rmdir` is an example of a simple (but realistic) BPF application. It
hook in dir remove and check the permission to remove a directory. If dir 
name with `can_not_rm` will raise Operation not permitted

Note: LSM may failed to load if the kernel is not configured as:

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_LSM=y
CONFIG_LSM="[other LSMs],bpf"
```
