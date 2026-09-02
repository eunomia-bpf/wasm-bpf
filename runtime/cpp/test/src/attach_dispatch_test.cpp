/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
// Pins the section-to-action mapping of fd_attach_action_for, which
// wasm_attach_bpf_program_fd consults before resolving any descriptor. That
// the resolver runs only in the attach-cgroup-by-fd arm is enforced by the
// structure of that function, not checked here. Needs neither root nor a
// kernel.
#include <assert.h>

#include "bpf-api.h"

int main() {
    assert(fd_attach_action_for("xdp", true) == fd_attach_action::reject_xdp);
    assert(fd_attach_action_for("xdp", false) == fd_attach_action::reject_xdp);
    assert(fd_attach_action_for("sockops", true) ==
           fd_attach_action::attach_cgroup_by_fd);
    assert(fd_attach_action_for("sockops", false) ==
           fd_attach_action::auto_attach);
    const char* auto_sections[] = {"tp_btf/sched_switch", "socket", ""};
    for (const char* section : auto_sections) {
        assert(fd_attach_action_for(section, true) ==
               fd_attach_action::auto_attach);
        assert(fd_attach_action_for(section, false) ==
               fd_attach_action::auto_attach);
    }
    return 0;
}
