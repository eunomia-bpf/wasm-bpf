// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "libbpf-wasm.h"
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "trace_helpers.h"

#include <inttypes.h>

#include <sys/types.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES 64
#define PERF_BUFFER_TIME_MS 10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS 100

#define NSEC_PER_SEC 1000000000ULL

// static volatile sig_atomic_t exiting = 0;

static struct env {
    pid_t pid;
    pid_t tid;
    uid_t uid;
    int duration;
    bool verbose;
    bool timestamp;
    bool print_uid;
    bool extended;
    bool failed;
    char* name;
} env = {.uid = INVALID_UID};

static int handle_event(void* ctx, void* data, size_t data_sz) {
    const struct event* e = data;
    struct tm* tm;
    int sps_cnt;
    char ts[32];
    time_t t;
    int fd, err;

    /* name filtering is currently done in user space */
    if (env.name && strstr(e->comm, env.name) == NULL)
        return 0;

    /* prepare fields */
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    if (e->ret >= 0) {
        fd = e->ret;
        err = 0;
    } else {
        fd = -1;
        err = -e->ret;
    }

    /* print output */
    sps_cnt = 0;
    if (env.timestamp) {
        printf("%-8s ", ts);
        sps_cnt += 9;
    }
    if (env.print_uid) {
        printf("%-7d ", e->uid);
        sps_cnt += 8;
    }
    printf("%-6d %-16s %3d %3d ", e->pid, e->comm, fd, err);
    sps_cnt += 7 + 17 + 4 + 4;
    if (env.extended) {
        printf("%08o ", e->flags);
        sps_cnt += 9;
    }
    printf("%s\n", e->fname);
    return 0;
}


int main(int argc, char** argv) {
    struct opensnoop_bpf* obj;
    __u64 time_end = 0;
    int err;

    obj = opensnoop_bpf__open();
    if (!obj) {
        fprintf(stdout, "failed to open BPF object\n");
        return 1;
    }
    /* initialize global data (filtering options) */
    obj->rodata->targ_tgid = env.pid;
    obj->rodata->targ_pid = env.tid;
    obj->rodata->targ_uid = env.uid;
    obj->rodata->targ_failed = env.failed;

    /* aarch64 and riscv64 don't have open syscall */
    if (!tracepoint_exists("syscalls", "sys_enter_open")) {
        bpf_program__set_autoload(
            obj->progs.tracepoint__syscalls__sys_enter_open, false);
        bpf_program__set_autoload(
            obj->progs.tracepoint__syscalls__sys_exit_open, false);
    }

    err = opensnoop_bpf__load(obj);
    if (err) {
        fprintf(stdout, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = opensnoop_bpf__attach(obj);
    if (err) {
        fprintf(stdout, "failed to attach BPF programs\n");
        goto cleanup;
    }
    printf("attach ok\n");
    /* print headers */
    if (env.timestamp)
        printf("%-8s ", "TIME");
    if (env.print_uid)
        printf("%-7s ", "UID");
    printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
    if (env.extended)
        printf("%-8s ", "FLAGS");
    printf("%s", "PATH");
    printf("\n");

    /* setup event callbacks */
    struct bpf_buffer* buf =
        bpf_buffer__open(obj->maps.events, handle_event, NULL);
    if (!buf) {
        err = -errno;
        fprintf(stdout, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    /* setup duration */
    if (env.duration)
        time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

    /* main: poll */
    while (true) {
        err = bpf_buffer__poll(buf, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stdout, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        if (env.duration && get_ktime_ns() > time_end)
            goto cleanup;
        /* reset err to return 0 if exiting */
        err = 0;
    }

cleanup:
    bpf_buffer__free(buf);
    opensnoop_bpf__destroy(obj);
    return err != 0;
}