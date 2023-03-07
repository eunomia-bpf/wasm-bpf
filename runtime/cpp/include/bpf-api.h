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
#include <vector>

#include "wasm_export.h"

#define POLL_TIMEOUT_MS 100
#define DEBUG_LIBBPF_RUNTIME 0

extern "C" {
struct bpf_buffer;
struct bpf_map;
struct bpf_object;
struct bpf_link;
void bpf_buffer__free(struct bpf_buffer *);
void bpf_object__close(struct bpf_object *object);
int bpf_link__destroy(struct bpf_link *link);
}

/// @brief init libbpf callbacks
void init_libbpf(void);
/// @brief bpf program instance
class wasm_bpf_program {
    std::unique_ptr<bpf_object, void (*)(bpf_object *obj)> obj{
        nullptr, bpf_object__close};
    std::unique_ptr<bpf_buffer, void (*)(bpf_buffer *obj)> buffer{
        nullptr, bpf_buffer__free};
    std::unordered_set<std::unique_ptr<bpf_link, int (*)(bpf_link *obj)>> links;

   public:
    int bpf_map_fd_by_name(const char *name);
    int load_bpf_object(const void *obj_buf, size_t obj_buf_sz);
    int attach_bpf_program(const char *name, const char *attach_target);
    int bpf_buffer_poll(wasm_exec_env_t exec_env, int fd, int32_t sample_func,
                        uint32_t ctx, void *buffer_data, size_t max_size,
                        int timeout_ms);
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
