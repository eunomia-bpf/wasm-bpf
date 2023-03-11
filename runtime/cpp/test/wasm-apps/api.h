#ifndef _API_H
#define _API_H
#include <inttypes.h>
#define IMPORT_MODULE "wasm_bpf"
#define ATTR(name) \
    __attribute__((import_module(IMPORT_MODULE), import_name(name)))
/// should be externref type for bpf_object_skel.
typedef uint64_t bpf_object_skel;
/// lookup a bpf map fd by name.
ATTR("wasm_bpf_map_fd_by_name")
int wasm_bpf_map_fd_by_name(bpf_object_skel obj, const char* name);
/// detach and close a bpf program.
ATTR("wasm_close_bpf_object")
int wasm_close_bpf_object(bpf_object_skel obj);
/// CO-RE load a bpf object into the kernel.
ATTR("wasm_load_bpf_object")
bpf_object_skel wasm_load_bpf_object(const void* obj_buf, int obj_buf_sz);
/// attach a bpf program to a kernel hook.
ATTR("wasm_attach_bpf_program")
int wasm_attach_bpf_program(bpf_object_skel obj,
                            const char* name,
                            const char* attach_target);
/// poll a bpf buffer, and call a wasm callback indicated by sample_func.
/// the first time to call this function will open and create a bpf buffer.
ATTR("wasm_bpf_buffer_poll")
int wasm_bpf_buffer_poll(bpf_object_skel program,
                         int fd,
                         int32_t sample_func,
                         uint32_t ctx,
                         char* data,
                         int max_size,
                         int timeout_ms);
/// lookup, update, delete, and get_next_key operations on a bpf map.
ATTR("wasm_bpf_map_operate")
int wasm_bpf_map_operate(int fd,
                         int cmd,
                         void* key,
                         void* value,
                         void* next_key,
                         uint64_t flags);

#endif