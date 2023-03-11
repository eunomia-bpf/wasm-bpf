/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 *
 * This is a minimal working example of wasm-bpf runtime implementation.
 */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <unordered_map>

#include "bpf-api.h"

using namespace std;
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
extern bool wasm_runtime_call_indirect(wasm_exec_env_t exec_env,
                                       uint32_t element_indices, uint32_t argc,
                                       uint32_t argv[]);
}
static int bpf_buffer_sample(void *ctx, void *data, size_t size);
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    if (DEBUG_LIBBPF_RUNTIME) return vfprintf(stderr, format, args);
    return 0;
}

/// @brief initialize libbpf library
void init_libbpf(void) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
}

/// @brief perf buffer sample callback
static void perfbuf_sample_fn(void *ctx, int cpu, void *data, __u32 size) {
    bpf_buffer_sample(ctx, data, size);
}


#define PERF_BUFFER_PAGES 64

class perf_buffer_wrapper : public bpf_buffer {
    std::unique_ptr<perf_buffer, void (*)(perf_buffer *pb)> inner{
        nullptr, perf_buffer__free};

   public:
    perf_buffer_wrapper(bpf_map *events) {
        bpf_map__set_type(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        bpf_map__set_key_size(events, sizeof(int));
        bpf_map__set_value_size(events, sizeof(int));
    }
    int bpf_buffer__poll(int timeout_ms) override {
        return perf_buffer__poll(inner.get(), timeout_ms);
    }
    int bpf_buffer__open(int fd, bpf_buffer_sample_fn sample_cb,
                         void *ctx) override {
        inner.reset(perf_buffer__new(fd, PERF_BUFFER_PAGES, perfbuf_sample_fn,
                                     NULL, ctx, NULL));
        return inner ? 0 : -EINVAL;
    }
};

struct ring_buffer_wrapper : public bpf_buffer {
   public:
    std::unique_ptr<ring_buffer, void (*)(ring_buffer *pb)> inner{
        nullptr, ring_buffer__free};
    ring_buffer_wrapper(bpf_map *events) {
        bpf_map__set_autocreate(events, false);
    }
    int bpf_buffer__poll(int timeout_ms) override {
        return ring_buffer__poll(inner.get(), timeout_ms);
    }
    int bpf_buffer__open(int fd, bpf_buffer_sample_fn sample_cb,
                         void *ctx) override {
        inner.reset(ring_buffer__new(fd, sample_cb, ctx, NULL));
        return inner ? 0 : -1;
    }
};

void bpf_buffer::set_callback_params(wasm_exec_env_t exec_env,
                                     uint32_t sample_func, void *data,
                                     size_t max_size, uint32_t ctx) {
    callback_exec_env = exec_env;
    wasm_sample_function = sample_func;
    poll_data = data;
    max_poll_size = max_size;
    wasm_ctx = ctx;
}

int bpf_buffer::bpf_buffer_sample(void *data, size_t size) {
    size_t sample_size = size;
    if (max_poll_size < size) {
        sample_size = max_poll_size;
    }
    memcpy(poll_data, data, sample_size);
    wasm_module_inst_t module_inst =
        wasm_runtime_get_module_inst(callback_exec_env);
    uint32_t argv[] = {wasm_ctx,
                       wasm_runtime_addr_native_to_app(module_inst, poll_data),
                       (uint32_t)size};
    // call the wasm callback handler
    if (!wasm_runtime_call_indirect(callback_exec_env, wasm_sample_function, 3,
                                    argv)) {
        printf("call func1 failed\n");
        return 0xDEAD;
    }
    return 0;
}

/// @brief verify that if an native address is valid in the wasm memory space
static inline bool verify_wasm_buffer_by_native_addr(wasm_exec_env_t exec_env,
                                                     void* ptr,
                                                     uint32_t length) {
    wasm_module_inst_t module = wasm_runtime_get_module_inst(exec_env);
    if (!module)
        return false;

    return wasm_runtime_validate_native_addr(module, ptr, length);
}
/// @brief verify that if a all chars of a zero-terminated string sit in the valid wasm memory space
static inline bool verify_wasm_string_by_native_addr(wasm_exec_env_t exec_env,
                                                     const char* str) {
    wasm_module_inst_t module = wasm_runtime_get_module_inst(exec_env);
    if (!module)
        return false;
    uint32_t wasm_addr = wasm_runtime_addr_native_to_app(module, (void*)str);
    return wasm_runtime_validate_app_str_addr(module, wasm_addr);
}

/// @brief sample the perf buffer and ring buffer
static int bpf_buffer_sample(void *ctx, void *data, size_t size) {
    bpf_buffer *buffer = (bpf_buffer *)ctx;
    return buffer->bpf_buffer_sample(data, size);
}

/// @brief create a bpf buffer based on the object map type
std::unique_ptr<bpf_buffer> bpf_buffer__new(struct bpf_map *events) {
    bool use_ringbuf = bpf_map__type(events) == BPF_MAP_TYPE_RINGBUF;
    if (use_ringbuf) {
        return std::make_unique<ring_buffer_wrapper>(events);
    } else {
        return std::make_unique<perf_buffer_wrapper>(events);
    }
    return nullptr;
}

/// Get the file descriptor of a map by name.
int wasm_bpf_program::bpf_map_fd_by_name(const char *name) {
    return bpf_object__find_map_fd_by_name(obj.get(), name);
}
/// @brief get map pointer by fd through iterating over all maps
bpf_map* wasm_bpf_program::map_ptr_by_fd(int fd) {
    bpf_map* curr = nullptr;
    bpf_map__for_each(curr, obj.get()) {
        if (bpf_map__fd(curr) == fd) {
            return curr;
        }
    }
    return nullptr;
}

/// @brief load all bpf programs and maps in a object file.
int wasm_bpf_program::load_bpf_object(const void *obj_buf, size_t obj_buf_sz) {
    auto object = bpf_object__open_mem(obj_buf, obj_buf_sz, NULL);
    if (!object) {
        return (int)libbpf_get_error(object);
    }
    obj.reset(object);
    return bpf_object__load(object);
}

static int attach_cgroup(struct bpf_program *prog, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Failed to open cgroup\n");
        return -1;
    }
    if (!bpf_program__attach_cgroup(prog, fd)) {
        printf("Prog %s failed to attach cgroup %s\n", bpf_program__name(prog),
               path);
        return -1;
    }
    close(fd);
    return 0;
}

/// @brief attach a specific bpf program by name and target.
/// support auto attach for most bpf program types:
/// tracepoint, kprobe, fentry, lsm, etc.
int wasm_bpf_program::attach_bpf_program(const char *name,
                                         const char *attach_target) {
    struct bpf_link *link;
    if (!attach_target) {
        // auto attach
        link = bpf_program__attach(
            bpf_object__find_program_by_name(obj.get(), name));
    } else {
        struct bpf_object *o = obj.get();
        struct bpf_program *prog = bpf_object__find_program_by_name(o, name);
        if (!prog) {
            printf("get prog %s fail", name);
            return -1;
        }
        const char *sec_name = bpf_program__section_name(prog);
        // TODO: support more attach type
        if (strcmp(sec_name, "sockops") == 0) {
            return attach_cgroup(prog, attach_target);
        } else {
            // try auto attach if new attach target is not supported
            link = bpf_program__attach(
                bpf_object__find_program_by_name(obj.get(), name));
        }
    }
    if (!link) {
        return (int)libbpf_get_error(link);
    }
    links.emplace(std::unique_ptr<bpf_link, int (*)(bpf_link * obj)>{
        link, bpf_link__destroy});
    return 0;
}

/// polling the buffer, if the buffer is not created, create it.
int wasm_bpf_program::bpf_buffer_poll(wasm_exec_env_t exec_env, int fd,
                                      int32_t sample_func, uint32_t ctx,
                                      void *data, size_t max_size,
                                      int timeout_ms) {
    if (buffer.get() == nullptr) {
        // create buffer
        auto map = this->map_ptr_by_fd(fd);
        buffer = bpf_buffer__new(map);
        buffer->bpf_buffer__open(fd, bpf_buffer_sample, buffer.get());
        return 0;
    }
    buffer->set_callback_params(exec_env, (uint32_t)sample_func, data, max_size,
                                ctx);
    // poll the buffer
    int res = buffer->bpf_buffer__poll(timeout_ms);
    if (res < 0) {
        return res;
    }
    return 0;
}

/// a wrapper function to call the bpf syscall
int bpf_map_operate(wasm_exec_env_t exec_env,
                    int fd,
                    int cmd,
                    void* key,
                    void* value,
                    void* next_key,
                    uint64_t flags) {
    bpf_map_info map_info;
    memset(&map_info, 0, sizeof(map_info));
    __u32 info_len = sizeof(map_info);
    int err;
    if ((err = bpf_map_get_info_by_fd(fd, &map_info, &info_len)) != 0) {
        // Invalid map fd
        return err;
    }
    auto key_size = map_info.key_size;
    auto value_size = map_info.value_size;

    auto verify_size = [&](void* ptr, uint32_t size) -> bool {
        return verify_wasm_buffer_by_native_addr(exec_env, ptr, size);
    };
    switch (cmd) {
        case BPF_MAP_GET_NEXT_KEY:
            if (!verify_size(key, key_size) || !verify_size(next_key, key_size))
                return -EFAULT;

            return bpf_map_get_next_key(fd, key, next_key);
        case BPF_MAP_LOOKUP_ELEM:
            if (!verify_size(key, key_size) || !verify_size(value, value_size))
                return -EFAULT;

            return bpf_map_lookup_elem_flags(fd, key, value, flags);
        case BPF_MAP_UPDATE_ELEM:
            if (!verify_size(key, key_size) || !verify_size(value, value_size))
                return -EFAULT;

            return bpf_map_update_elem(fd, key, value, flags);
        case BPF_MAP_DELETE_ELEM:
            if (!verify_size(key, key_size))
                return -EFAULT;

            return bpf_map_delete_elem_flags(fd, key, flags);
        default:  // More syscall commands can be allowed here
            return -EINVAL;
    }
    return -EINVAL;
}

extern "C" {
uint64_t wasm_load_bpf_object(wasm_exec_env_t exec_env, void *obj_buf,
                              int obj_buf_sz) {
    if (obj_buf_sz <= 0) return 0;
    // Ensure that the buffer passed from wasm program is valid
    if (!verify_wasm_buffer_by_native_addr(exec_env, obj_buf,
                                           (uint32_t)obj_buf_sz)) {
        return 0;
    }
    bpf_program_manager *bpf_programs =
        (bpf_program_manager *)wasm_runtime_get_user_data(exec_env);
    auto program = std::make_unique<wasm_bpf_program>();
    int res = program->load_bpf_object(obj_buf, (size_t)obj_buf_sz);
    if (res < 0) return 0;
    auto key = (uint64_t)program.get();
    bpf_programs->emplace(key, std::move(program));
    return key;
}

int wasm_close_bpf_object(wasm_exec_env_t exec_env, uint64_t program) {
    bpf_program_manager* bpf_programs =
        (bpf_program_manager*)wasm_runtime_get_user_data(exec_env);
    if (!bpf_programs->count(program))
        return 0;
    return !bpf_programs->erase(program);
}

int wasm_attach_bpf_program(wasm_exec_env_t exec_env, uint64_t program,
                            char *name, char *attach_target) {
    bpf_program_manager* bpf_programs =
        (bpf_program_manager*)wasm_runtime_get_user_data(exec_env);
    if (bpf_programs->find(program) != bpf_programs->end()) {
        // Ensure that the string pointer passed from wasm program is valid
        if ((!verify_wasm_string_by_native_addr(exec_env, name)) ||
            (!verify_wasm_string_by_native_addr(exec_env, attach_target)))
            return -EFAULT;
        return (*bpf_programs)[program]->attach_bpf_program(name,
                                                            attach_target);
    }
    return -EINVAL;
}

int wasm_bpf_buffer_poll(wasm_exec_env_t exec_env, uint64_t program, int fd,
                         int32_t sample_func, uint32_t ctx, char *data,
                         int max_size, int timeout_ms) {
    bpf_program_manager *bpf_programs =
        (bpf_program_manager *)wasm_runtime_get_user_data(exec_env);
    if (bpf_programs->find(program) != bpf_programs->end()) {
        // Ensure that the buffer is valid and can hold the data received
        if (!verify_wasm_buffer_by_native_addr(exec_env, data, (uint32_t)max_size))
            return -EFAULT;
        return (*bpf_programs)[program]->bpf_buffer_poll(
            exec_env, fd, sample_func, ctx, data, (size_t)max_size, timeout_ms);
    }
    return -EINVAL;
}

int wasm_bpf_map_fd_by_name(wasm_exec_env_t exec_env, uint64_t program,
                            const char *name) {
    bpf_program_manager *bpf_programs =
        (bpf_program_manager *)wasm_runtime_get_user_data(exec_env);
    if (bpf_programs->find(program) != bpf_programs->end()) {
        // Ensure that the string is valid
        if (!verify_wasm_string_by_native_addr(exec_env, name))
            return -EFAULT;
        return (*bpf_programs)[program]->bpf_map_fd_by_name(name);
    }
    return -EINVAL;
}

/// @brief a wrapper function to the bpf syscall to operate the bpf maps
int wasm_bpf_map_operate(wasm_exec_env_t exec_env,
                         int fd,
                         int cmd,
                         void* key,
                         void* value,
                         void* next_key,
                         uint64_t flags) {
    return bpf_map_operate(
        exec_env, fd, (bpf_map_cmd)cmd, key, value, next_key, flags);
}
}

int wasm_main(unsigned char *buf, unsigned int size, int argc, char *argv[]) {
    char error_buf[128];
    int exit_code = 0;
    char *wasm_path = NULL;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32_t stack_size = 1 << 20, heap_size = 1 << 20;
    wasm_function_inst_t start_func = NULL;
    uint32_t wasm_buffer = 0;
    RuntimeInitArgs init_args;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_libbpf();
    // init wasm host functions
    static NativeSymbol native_symbols[] = {
        EXPORT_WASM_API_WITH_SIG(wasm_load_bpf_object, "(*~)I"),
        EXPORT_WASM_API_WITH_SIG(wasm_attach_bpf_program, "(I$$)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_buffer_poll, "(Iiii*~i)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_map_fd_by_name, "(I$)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_map_operate, "(ii***I)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_close_bpf_object, "(I)i"),
    };
    init_args.mem_alloc_type = Alloc_With_System_Allocator;
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "wasm_bpf";
    init_args.native_symbols = native_symbols;
    // init runtime and wasi
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }
    module = wasm_runtime_load(buf, size, error_buf, sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        return -1;
    }
    wasm_runtime_set_wasi_args(module, NULL, 0, NULL, 0, NULL, 0, argv, argc);
    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));
    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        return -1;
    }
    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        return -1;
    }
    bpf_program_manager prog_manager;
    wasm_runtime_set_user_data(exec_env, &prog_manager);
    wasm_runtime_set_module_inst(exec_env, module_inst);
    if (!(start_func = wasm_runtime_lookup_wasi_start_function(module_inst))) {
        printf("The start wasm function is not found.\n");
        return -1;
    }
    // start running the wasm module
    if (!wasm_runtime_call_wasm(exec_env, start_func, 0, NULL)) {
        printf("Call wasm function start failed. %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    exit_code = (int)wasm_runtime_get_wasi_exit_code(module_inst);
    if (exec_env) wasm_runtime_destroy_exec_env(exec_env);
    if (module_inst) {
        if (wasm_buffer) {
            wasm_runtime_module_free(module_inst, wasm_buffer);
        }
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module) wasm_runtime_unload(module);
    wasm_runtime_destroy();
    return exit_code;
}
