
#include <inttypes.h>

/// should be externref type for bpf_object_skel.
typedef uint64_t bpf_object_skel;
/// lookup a bpf map fd by name.
int wasm_bpf_map_fd_by_name(bpf_object_skel obj, const char* name) {
    return 0;
}
/// detach and close a bpf program.
int wasm_close_bpf_object(bpf_object_skel obj) {
    return 0;
}
/// CO-RE load a bpf object into the kernel.
bpf_object_skel wasm_load_bpf_object(const void* obj_buf, int obj_buf_sz) {
    return 0;
}
/// attach a bpf program to a kernel hook.
int wasm_attach_bpf_program(bpf_object_skel obj,
                            const char* name,
                            const char* attach_target) {
    return 0;
}
/// poll a bpf buffer, and call a wasm callback indicated by sample_func.
/// the first time to call this function will open and create a bpf buffer.
int wasm_bpf_buffer_poll(bpf_object_skel program,
                         int fd,
                         int32_t sample_func,
                         uint32_t ctx,
                         char* data,
                         int max_size,
                         int timeout_ms) {
    return 0;
}
/// lookup, update, delete, and get_next_key operations on a bpf map.
int wasm_bpf_map_operate(int fd,
                         int cmd,
                         void* key,
                         void* value,
                         void* next_key,
                         uint64_t flags) {
    return 0;
}