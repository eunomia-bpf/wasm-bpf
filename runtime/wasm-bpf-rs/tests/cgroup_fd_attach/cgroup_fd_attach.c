#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wasi/api.h>
#include "libbpf-wasm.h"
#include "base64decode.h"
#include "sockops.data.h"

#define IMPORT_MODULE "wasm_bpf"
#define ATTR(name) \
    __attribute__((import_module(IMPORT_MODULE), import_name(name)))
/// attach a bpf program to a hook point named by a file descriptor. Declared here instead of
/// taken from the SDK header, which lives in a submodule that is updated separately.
ATTR("wasm_attach_bpf_program_fd")
int wasm_attach_bpf_program_fd(bpf_object_skel obj,
                               const char* name,
                               int target_fd);
#undef IMPORT_MODULE
#undef ATTR

/// Where the runtime is asked to put the host cgroup v2 root.
#define CGROUP_MOUNT_POINT "/guestmnt"
#define SOCKOPS_PROG_NAME "pid_tcp_opt_inject"
/// A descriptor number the guest was never given.
#define UNOPENED_FD 999999

/// Find the descriptor the runtime preopened for `guest_path`. Only descriptors the host itself
/// preopened resolve to anything, so this walks the prestat table rather than opening a path of
/// its own.
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

int main(void) {
    size_t len = strlen(sockops_data);
    size_t out_len;
    const char* buf = (const char*)base64_decode(sockops_data, len, &out_len);
    bpf_object_skel obj = wasm_load_bpf_object(buf, out_len);
    if (obj == 0) {
        printf("Failed to load the bpf object\n");
        return 1;
    }
    int cgroup_fd = find_preopen_fd(CGROUP_MOUNT_POINT);
    if (cgroup_fd < 0) {
        printf("No directory preopened at " CGROUP_MOUNT_POINT "\n");
        return 1;
    }

    // A descriptor that was never opened names nothing the host can attach to.
    if (wasm_attach_bpf_program_fd(obj, SOCKOPS_PROG_NAME, UNOPENED_FD) == 0) {
        printf("Attach accepted a descriptor that was never opened\n");
        return 1;
    }
    // stdout is open in the guest, but it is not a directory the host preopened.
    if (wasm_attach_bpf_program_fd(obj, SOCKOPS_PROG_NAME, 1) == 0) {
        printf("Attach accepted stdout as a target\n");
        return 1;
    }
    // Neither is a directory the guest opened for itself, even though it is a live handle onto
    // the very cgroup that is about to be attached to.
    int own_fd = open(CGROUP_MOUNT_POINT, O_RDONLY | O_DIRECTORY);
    if (own_fd >= 0) {
        if (wasm_attach_bpf_program_fd(obj, SOCKOPS_PROG_NAME, own_fd) == 0) {
            printf("Attach accepted a directory the guest opened itself\n");
            return 1;
        }
        close(own_fd);
    }

    if (wasm_attach_bpf_program_fd(obj, SOCKOPS_PROG_NAME, cgroup_fd) != 0) {
        printf("Failed to attach sockops to the preopened cgroup\n");
        return 1;
    }
    printf("Attached sockops to the preopened cgroup by descriptor\n");
    fflush(stdout);
    while (true) {
        sleep(10);
    }
}
