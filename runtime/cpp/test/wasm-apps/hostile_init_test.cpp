/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
// Proves the preopened directory is unreachable while the module is being
// instantiated. The runtime calls the exported __post_instantiate during
// wasm_runtime_instantiate, before the runtime injects any preopen, so the
// probe below runs at instantiation time. It speaks raw WASI instead of
// going through libc: a command module's libc preopen table is filled only
// once _start runs, so a libc call here would fail even in a world where
// the directory was reachable, and prove nothing. A breach is any SUCCESS;
// the errno of a failure is never consulted, so an unexpected error cannot
// mask one. This test must fail if preopen setup ever moves back before
// instantiation.
#include <stdio.h>
#include <wasi/api.h>

/// 0 until the probe runs. The runtime silently skips a __post_instantiate
/// export it does not recognize, so main refuses to pass judgment unless the
/// probe genuinely ran.
static int probe_ran = 0;
/// 1 when any instantiation-time access to the directory succeeded.
static int probe_breached = 0;

__attribute__((export_name("__post_instantiate"))) void probe_during_init(
    void) {
    probe_ran = 1;
    // Under the fixed runtime nothing is seated at fd 3 during
    // instantiation, so the prestat probe fails and everything is denied.
    // If preopen setup ever moved back before instantiation, the prestat
    // would answer and the opens below would succeed at full rights.
    __wasi_prestat_t prestat;
    if (__wasi_fd_prestat_get(3, &prestat) != __WASI_ERRNO_SUCCESS) {
        return;
    }
    __wasi_fd_t opened;
    __wasi_errno_t err = __wasi_path_open(3, 0, "cgroup.procs", 0,
                                          __WASI_RIGHTS_FD_READ, 0, 0, &opened);
    if (err == __WASI_ERRNO_SUCCESS) {
        probe_breached = 1;
        __wasi_fd_close(opened);
        return;
    }
    err = __wasi_path_open(3, 0, ".", __WASI_OFLAGS_DIRECTORY,
                           __WASI_RIGHTS_FD_READDIR, 0, 0, &opened);
    if (err == __WASI_ERRNO_SUCCESS) {
        probe_breached = 1;
        __wasi_fd_close(opened);
    }
}

/// Runs from _start, well after the probe; the crt maps the return value to
/// the exit code. Exit 0: the probe ran and every access was denied. Exit 9:
/// something got through during instantiation. Exit 10: the probe never ran,
/// so nothing was proven and the test must not pass.
int main() {
    if (!probe_ran) {
        printf("Init probe never ran\n");
        return 10;
    }
    if (probe_breached) {
        printf("Preopen was reachable during instantiation\n");
        return 9;
    }
    printf("Preopen unreachable during instantiation\n");
    return 0;
}
