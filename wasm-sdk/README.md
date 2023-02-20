# SDK

This directory contains SDKs that can be used by eBPF user-space programs.

- [c](./c): A C Header contains the prototype of host functions provided by the runtime, and some wrapper functions around them.
- [rust](./rust) A rust crate `wasm-bpf-binding` that contains the prototype of several host-provided functions.

Don't worry you are using other languages, you can just add these function imports (in the format your language used) to use functions provided by the runtime:

```c
/// lookup a bpf map fd by name.
i32 wasm_bpf_map_fd_by_name(u64 obj, u32 name);
/// detach and close a bpf program.
i32 wasm_close_bpf_object(u64 obj);
/// CO-RE load a bpf object into the kernel.
u64 wasm_load_bpf_object(u32 obj_buf, u32 obj_buf_sz);
/// attach a bpf program to a kernel hook.
i32 wasm_attach_bpf_program(u64 obj, u32 name,
                            u32 attach_target);
/// poll a bpf buffer, and call a wasm callback indicated by sample_func.
/// the first time to call this function will open and create a bpf buffer.
i32 wasm_bpf_buffer_poll(u64 program, i32 fd, u32 sample_func,
                         u32 ctx, u32 data, i32 max_size,
                         i32 timeout_ms);
/// lookup, update, delete, and get_next_key operations on a bpf map.
i32 wasm_bpf_map_operate(u64 fd, i32 cmd, u32 key, u32 value,
                         u32 next_key, u64 flags);
```

- `iXX` denotes signed integer with `XX` bits
- `uXX` denotes unsigned integer with `XX` bits

