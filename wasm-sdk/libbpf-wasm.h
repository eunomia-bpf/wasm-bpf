#ifndef _LIBBPF_WASM_H
#define _LIBBPF_WASM_H

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define POLL_TIMEOUT_MS 100
/// should be externref type for bpf_object_skel.
typedef uint64_t bpf_object_skel;
/// lookup a bpf map fd by name.
int wasm_bpf_map_fd_by_name(bpf_object_skel obj, const char *name);
/// detach and close a bpf program.
int wasm_close_bpf_object(bpf_object_skel obj);
/// CO-RE load a bpf object into the kernel.
bpf_object_skel wasm_load_bpf_object(const void *obj_buf, int obj_buf_sz);
/// attach a bpf program to a kernel hook.
int wasm_attach_bpf_program(bpf_object_skel obj, const char *name,
                            const char *attach_target);
/// poll a bpf buffer, and call a wasm callback indicated by sample_func.
/// the first time to call this function will open and create a bpf buffer.
int wasm_bpf_buffer_poll(bpf_object_skel program, int fd, int32_t sample_func,
                         uint32_t ctx, char *data, int max_size,
                         int timeout_ms);
/// lookup, update, delete, and get_next_key operations on a bpf map.
int wasm_bpf_map_operate(int fd, int cmd, void *key, void *value,
                         void *next_key, uint64_t flags);

struct bpf_map {
    bpf_object_skel obj_ptr;
    char name[64];
};

struct bpf_program {
    bpf_object_skel obj_ptr;
    char name[64];
    char attach_target[128];
    bool autoattach;
};

struct bpf_map_skeleton {
    const char *name;
    struct bpf_map **map;
    void **mmaped;
};

struct bpf_prog_skeleton {
    const char *name;
    struct bpf_program **prog;
};

struct bpf_object_skeleton {
    size_t sz; /* size of this struct, for forward/backward compatibility */
    const char *name;
    const void *data;
    size_t data_sz;

    bpf_object_skel obj;

    int map_cnt;
    int map_skel_sz; /* sizeof(struct bpf_map_skeleton) */
    struct bpf_map_skeleton *maps;

    int prog_cnt;
    int prog_skel_sz; /* sizeof(struct bpf_prog_skeleton) */
    struct bpf_prog_skeleton *progs;
};

/*
    set the bpf prog attach taeget, for example:
        sockops need to set attach cgroup
        sockfilter need to set attach nic
        ...

    runtime will according to the section name to attach the correspond target
*/
static void bpf_set_prog_attach_target(struct bpf_program *prog, char* attach_target){
    strncpy(prog->attach_target, attach_target, sizeof(prog->attach_target));
}

/* handle errno-based (e.g., syscall or libc) errors according to libbpf's
 * strict mode settings
 */
static inline int libbpf_err_errno(int ret) {
    /* errno is already assumed to be set on error */
    return ret < 0 ? -errno : ret;
}

static int bpf_map__fd(const struct bpf_map *map) {
    return wasm_bpf_map_fd_by_name(map->obj_ptr, map->name);
}
struct bpf_object_open_opts;
static int bpf_object__open_skeleton(struct bpf_object_skeleton *s,
                                     const struct bpf_object_open_opts *opts) {
    printf("\n");
    assert(s && s->data && s->data_sz);

    for (int i = 0; i < s->map_cnt; i++) {
        struct bpf_map_skeleton *map_skel =
            (void *)s->maps + i * s->map_skel_sz;
        *map_skel->map = calloc(1, sizeof(**map_skel->map));
        if (!*map_skel->map) return -1;
        strncpy((*map_skel->map)->name, map_skel->name,
                sizeof((*map_skel->map)->name));
    }

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        *prog_skel->prog = calloc(1, sizeof(**prog_skel->prog));
        if (!*prog_skel->prog) return -1;
        strncpy((*prog_skel->prog)->name, prog_skel->name,
                sizeof((*prog_skel->prog)->name));
    }

    return 0;
}

static int bpf_object__detach_skeleton(struct bpf_object_skeleton *s) {
    return 0;
}

static int bpf_object__load_skeleton(struct bpf_object_skeleton *s) {
    assert(s && s->data && s->data_sz);
    s->obj = wasm_load_bpf_object(s->data, s->data_sz);
    if (!s->obj) return -1;

    for (int i = 0; i < s->map_cnt; i++) {
        struct bpf_map_skeleton *map_skel =
            (void *)s->maps + i * s->map_skel_sz;
        if (!*map_skel->map) return -1;
        (*map_skel->map)->obj_ptr = s->obj;
    }

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        if (!*prog_skel->prog) return -1;
        (*prog_skel->prog)->obj_ptr = s->obj;
    }
    return 0;
}

static int bpf_object__attach_skeleton(struct bpf_object_skeleton *s) {
    assert(s && s->data && s->data_sz);

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        if (prog_skel->prog && *prog_skel->prog)
            wasm_attach_bpf_program(s->obj, (*prog_skel->prog)->name,
                                    (*prog_skel->prog)->attach_target);
    }
    return 0;
}

static void bpf_object__destroy_skeleton(struct bpf_object_skeleton *s) {
    if (!s) return;

    if (s->obj) wasm_close_bpf_object(s->obj);
    free(s->maps);
    free(s->progs);
    free(s);
}

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct bpf_buffer {
    struct bpf_map *events;
    int fd;
    void *ctx;
    bpf_buffer_sample_fn sample_fn;
};

static struct bpf_buffer *bpf_buffer__new(struct bpf_map *events) {
    struct bpf_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return NULL;
    buffer->events = events;
    return buffer;
}

static struct bpf_buffer *bpf_buffer__open(struct bpf_map *events,
                                           bpf_buffer_sample_fn sample_cb,
                                           void *ctx) {
    struct bpf_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return NULL;
    buffer->events = events;
    buffer->ctx = ctx;
    buffer->fd = bpf_map__fd(buffer->events);
    buffer->sample_fn = sample_cb;
    return buffer;
}

static int bpf_buffer__poll(struct bpf_buffer *buffer, int timeout_ms) {
    assert(buffer && buffer->events && buffer->sample_fn);
    if (timeout_ms <= 0) timeout_ms = POLL_TIMEOUT_MS;
    char event_buffer[4096];
    int res = wasm_bpf_buffer_poll(
        buffer->events->obj_ptr, buffer->fd, (int32_t)buffer->sample_fn,
        (uint32_t)buffer->ctx, event_buffer, 4096, timeout_ms);
    return res;
}

static void bpf_buffer__free(struct bpf_buffer *buffer) {
    assert(buffer);
    free(buffer);
}

static int bpf_program__set_autoload(struct bpf_program *prog, bool autoload) {
    // TODO: implement
    prog->autoattach = autoload;
    return 0;
}

/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
    BPF_ANY = 0,     /* create new element or update existing */
    BPF_NOEXIST = 1, /* create new element if it didn't exist */
    BPF_EXIST = 2,   /* update existing element */
    BPF_F_LOCK = 4,  /* spin_lock-ed map_lookup/map_update */
};

// Note that we limit the valid bpf_cmd to map operations only.
enum bpf_cmd {
    // BPF_MAP_CREATE,
    BPF_MAP_LOOKUP_ELEM = 1,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    // BPF_PROG_LOAD,
    // BPF_OBJ_PIN,
    // BPF_OBJ_GET,
    // BPF_PROG_ATTACH,
    // BPF_PROG_DETACH,
    // BPF_PROG_TEST_RUN,
    // BPF_PROG_RUN = BPF_PROG_TEST_RUN,
    // BPF_PROG_GET_NEXT_ID,
    // BPF_MAP_GET_NEXT_ID,
    // BPF_PROG_GET_FD_BY_ID,
    // BPF_MAP_GET_FD_BY_ID,
    // BPF_OBJ_GET_INFO_BY_FD,
    // BPF_PROG_QUERY,
    // BPF_RAW_TRACEPOINT_OPEN,
    // BPF_BTF_LOAD,
    // BPF_BTF_GET_FD_BY_ID,
    // BPF_TASK_FD_QUERY,
    // BPF_MAP_LOOKUP_AND_DELETE_ELEM,
    // BPF_MAP_FREEZE,
    // BPF_BTF_GET_NEXT_ID,
    // BPF_MAP_LOOKUP_BATCH,
    // BPF_MAP_LOOKUP_AND_DELETE_BATCH,
    // BPF_MAP_UPDATE_BATCH,
    // BPF_MAP_DELETE_BATCH,
    // BPF_LINK_CREATE,
    // BPF_LINK_UPDATE,
    // BPF_LINK_GET_FD_BY_ID,
    // BPF_LINK_GET_NEXT_ID,
    // BPF_ENABLE_STATS,
    // BPF_ITER_CREATE,
    // BPF_LINK_DETACH,
    // BPF_PROG_BIND_MAP,
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
    /* BPF_MAP_TYPE_CGROUP_STORAGE is available to bpf programs attaching
     * to a cgroup. The newer BPF_MAP_TYPE_CGRP_STORAGE is available to
     * both cgroup-attached and other progs and supports all functionality
     * provided by BPF_MAP_TYPE_CGROUP_STORAGE. So mark
     * BPF_MAP_TYPE_CGROUP_STORAGE deprecated.
     */
    BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_INODE_STORAGE,
    BPF_MAP_TYPE_TASK_STORAGE,
    BPF_MAP_TYPE_BLOOM_FILTER,
    BPF_MAP_TYPE_USER_RINGBUF,
    BPF_MAP_TYPE_CGRP_STORAGE,
};

/* Note that tracing related programs such as
 * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
 * are not subject to a stable API since kernel internal data
 * structures can change from release to release and may
 * therefore break existing tracing BPF programs. Tracing BPF
 * programs correspond to /a/ specific kernel which is to be
 * analyzed, and not /a/ specific kernel /and/ all future ones.
 */
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
    BPF_PROG_TYPE_FLOW_DISSECTOR,
    BPF_PROG_TYPE_CGROUP_SYSCTL,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    BPF_PROG_TYPE_CGROUP_SOCKOPT,
    BPF_PROG_TYPE_TRACING,
    BPF_PROG_TYPE_STRUCT_OPS,
    BPF_PROG_TYPE_EXT,
    BPF_PROG_TYPE_LSM,
    BPF_PROG_TYPE_SK_LOOKUP,
    BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
};

enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_SOCK_CREATE,
    BPF_CGROUP_SOCK_OPS,
    BPF_SK_SKB_STREAM_PARSER,
    BPF_SK_SKB_STREAM_VERDICT,
    BPF_CGROUP_DEVICE,
    BPF_SK_MSG_VERDICT,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_LIRC_MODE2,
    BPF_FLOW_DISSECTOR,
    BPF_CGROUP_SYSCTL,
    BPF_CGROUP_UDP4_RECVMSG,
    BPF_CGROUP_UDP6_RECVMSG,
    BPF_CGROUP_GETSOCKOPT,
    BPF_CGROUP_SETSOCKOPT,
    BPF_TRACE_RAW_TP,
    BPF_TRACE_FENTRY,
    BPF_TRACE_FEXIT,
    BPF_MODIFY_RETURN,
    BPF_LSM_MAC,
    BPF_TRACE_ITER,
    BPF_CGROUP_INET4_GETPEERNAME,
    BPF_CGROUP_INET6_GETPEERNAME,
    BPF_CGROUP_INET4_GETSOCKNAME,
    BPF_CGROUP_INET6_GETSOCKNAME,
    BPF_XDP_DEVMAP,
    BPF_CGROUP_INET_SOCK_RELEASE,
    BPF_XDP_CPUMAP,
    BPF_SK_LOOKUP,
    BPF_XDP,
    BPF_SK_SKB_VERDICT,
    BPF_SK_REUSEPORT_SELECT,
    BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
    BPF_PERF_EVENT,
    BPF_TRACE_KPROBE_MULTI,
    BPF_LSM_CGROUP,
    __MAX_BPF_ATTACH_TYPE
};

static int bpf_map_update_elem(int fd, const void *key, const void *value,
                               uint64_t flags) {
    return wasm_bpf_map_operate(fd, BPF_MAP_UPDATE_ELEM, (void *)key,
                                (void *)value, NULL, flags);
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value) {
    return wasm_bpf_map_operate(fd, BPF_MAP_LOOKUP_ELEM, (void *)key, value,
                                NULL, 0);
}

static int bpf_map_lookup_elem_flags(int fd, const void *key, void *value,
                                     uint64_t flags) {
    return wasm_bpf_map_operate(fd, BPF_MAP_LOOKUP_ELEM, (void *)key, value,
                                NULL, flags);
}

static int bpf_map_delete_elem(int fd, const void *key) {
    return wasm_bpf_map_operate(fd, BPF_MAP_DELETE_ELEM, (void *)key, NULL,
                                NULL, 0);
}

static int bpf_map_delete_elem_flags(int fd, const void *key, uint64_t flags) {
    return wasm_bpf_map_operate(fd, BPF_MAP_DELETE_ELEM, (void *)key, NULL,
                                NULL, flags);
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key) {
    return wasm_bpf_map_operate(fd, BPF_MAP_GET_NEXT_KEY, (void *)key, NULL,
                                next_key, 0);
}

#endif  // _LIBBPF_WASM_H
