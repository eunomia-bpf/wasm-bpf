/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 *
 * This is a minimal working example of wasm-bpf runtime implementation.
 */
#ifndef __BPF_WASM_API_H
#define __BPF_WASM_API_H

#include <cstdlib>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <bpf/libbpf.h>
#include "wasm_export.h"

#define POLL_TIMEOUT_MS 100
#define DEBUG_LIBBPF_RUNTIME 0

extern "C" {
struct bpf_map;
struct bpf_object;
struct bpf_link;
void bpf_object__close(struct bpf_object *object);
int bpf_link__destroy(struct bpf_link *link);
}

/// @brief init libbpf callbacks
void init_libbpf(void);

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, size_t size);

/// An absraction of a bpf ring buffer or perf buffer copied from bcc.
/// see https://github.com/iovisor/bcc/blob/master/libbpf-tools/compat.c
class bpf_buffer {
    bpf_buffer_sample_fn fn;
    wasm_exec_env_t callback_exec_env;
    uint32_t wasm_ctx;
    uint32_t wasm_sample_function;
    void *poll_data;
    size_t max_poll_size;

   public:
    /// @brief sample callback which calls the wasm handler indirectly
    int bpf_buffer_sample(void *data, size_t size);
    /// @brief set the wasm callback parameters
    void set_callback_params(wasm_exec_env_t exec_env, uint32_t sample_func,
                             void *data, size_t max_size, uint32_t ctx);
    /// @brief polling the bpf buffer
    virtual int bpf_buffer__poll(int timeout_ms) = 0;
    /// @brief open the bpf buffer map
    virtual int bpf_buffer__open(int fd, bpf_buffer_sample_fn sample_cb,
                                 void *ctx) = 0;
    virtual ~bpf_buffer() = default;
};

/// @brief bpf program instance
class wasm_bpf_program {
    std::unique_ptr<bpf_object, void (*)(bpf_object *obj)> obj{
        nullptr, bpf_object__close};
    std::unique_ptr<bpf_buffer> buffer;
    std::unordered_set<std::unique_ptr<bpf_link, int (*)(bpf_link *obj)>> links;

   public:
    int bpf_map_fd_by_name(const char *name);
    int load_bpf_object(const void* obj_buf,
                        size_t obj_buf_sz);
    int attach_bpf_program(const char *name, const char *attach_target);
    int bpf_buffer_poll(wasm_exec_env_t exec_env, int fd, int32_t sample_func,
                        uint32_t ctx, void *buffer_data, size_t max_size,
                        int timeout_ms);
    bpf_map* map_ptr_by_fd(int fd);
};

/// @brief A user data structure whose instance will be shared in a wasm
/// runtime. It will store a map containing id->bpf_program and map fds opened
/// by a bpf program
/// Note that we need to remove fds opened by a bpf program when it's closed
struct bpf_program_manager {
    std::unordered_map<uint64_t, std::unique_ptr<wasm_bpf_program>> programs;
};
enum bpf_map_cmd {
    _BPF_MAP_LOOKUP_ELEM = 1,
    _BPF_MAP_UPDATE_ELEM,
    _BPF_MAP_DELETE_ELEM,
    _BPF_MAP_GET_NEXT_KEY,
};
/// Operate on a bpf map.
int bpf_map_operate(int fd, int cmd, void *key, void *value, void *next_key,
                    uint64_t flags);
extern "C" {
/// The main entry, argc and argv will be passed to the wasm module.
int wasm_main(unsigned char *buf, unsigned int size, int argc, char *argv[]);
}

#endif
