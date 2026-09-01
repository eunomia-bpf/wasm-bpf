/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
// Checks the fd-based attach boundary from inside the sandbox: the sealed
// preopen denies open, create, and list beneath it; descriptors the runtime
// did not preopen are refused by the attach call; the preopened descriptor
// attaches. Every failure exits with its own code so the driver log says
// which check broke.
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wasi/api.h>

#include "../asserts/sockops.data.h"
#include "api.h"
#include "base64decode.h"

#define CGROUP_MOUNT_POINT "/sys/fs/cgroup"
#define SOCKOPS_PROG_NAME "pid_tcp_opt_inject"
/// A descriptor number the guest was never given.
#define UNOPENED_FD 999999

/// Find the descriptor the runtime preopened for `guest_path` by walking the
/// prestat table, the only way a guest can see a preopen. Breaking at the
/// first failure relies on WAMR numbering preopens consecutively from fd 3,
/// so the walk stops at the first gap.
static int find_preopen_fd(const char* guest_path) {
    char name[256];
    for (__wasi_fd_t fd = 3; fd < 128; fd++) {
        __wasi_prestat_t prestat;
        if (__wasi_fd_prestat_get(fd, &prestat) != __WASI_ERRNO_SUCCESS)
            break;
        if (prestat.tag != __WASI_PREOPENTYPE_DIR)
            continue;
        size_t len = prestat.u.dir.pr_name_len;
        if (len >= sizeof(name))
            continue;
        if (__wasi_fd_prestat_dir_name(fd, (uint8_t*)name, len) !=
            __WASI_ERRNO_SUCCESS)
            continue;
        name[len] = '\0';
        if (strcmp(name, guest_path) == 0)
            return (int)fd;
    }
    return -1;
}

int main(int argc, char** argv) {
    size_t len = strlen(sockops_data);
    size_t out_len;
    const char* buf = (const char*)base64_decode(sockops_data, len, &out_len);
    bpf_object_skel handle = wasm_load_bpf_object(buf, out_len);
    if (handle == 0) {
        printf("Failed to load the sockops object\n");
        return 1;
    }
    int cgroup_fd = find_preopen_fd(CGROUP_MOUNT_POINT);
    if (cgroup_fd < 0) {
        printf("No directory preopened at " CGROUP_MOUNT_POINT "\n");
        return 2;
    }

    // The preopen is sealed: a file that exists beneath it cannot be opened,
    // nothing can be created beneath it, and it cannot be listed.
    if (open(CGROUP_MOUNT_POINT "/cgroup.procs", O_RDONLY) >= 0) {
        printf("Opening a file under the sealed preopen succeeded\n");
        return 3;
    }
    if (mkdir(CGROUP_MOUNT_POINT "/made-by-guest", 0755) == 0) {
        printf("Creating a directory under the sealed preopen succeeded\n");
        return 4;
    }
    if (opendir(CGROUP_MOUNT_POINT) != NULL) {
        printf("Listing the sealed preopen succeeded\n");
        return 5;
    }

    // A descriptor that was never opened names nothing the host can attach
    // to, and stdout is open in the guest but not a preopened directory. A
    // closed preopen cannot be tried (WASI refuses to close a preopen), nor
    // can a directory the guest opened itself (the seal makes that open
    // fail); the runtime's registry checks cover those.
    if (wasm_attach_bpf_program_fd(handle, SOCKOPS_PROG_NAME, UNOPENED_FD) ==
        0) {
        printf("Attach accepted a descriptor that was never opened\n");
        return 6;
    }
    if (wasm_attach_bpf_program_fd(handle, SOCKOPS_PROG_NAME, 1) == 0) {
        printf("Attach accepted stdout as a target\n");
        return 7;
    }

    // The driver probed the environment natively and passed the verdict in.
    // When the same attach succeeded there, a failure here is a regression,
    // never a skip.
    bool expect = argc > 1 && strcmp(argv[1], "expect-attach") == 0;
    if (wasm_attach_bpf_program_fd(handle, SOCKOPS_PROG_NAME, cgroup_fd) != 0) {
        if (expect) {
            printf("Attach failed although this environment supports it\n");
            return 8;
        }
        printf("SKIP: sockops attach not supported on this kernel\n");
        return 0;
    }
    printf("Attached sockops to the preopened cgroup by descriptor\n");
    return 0;
}
