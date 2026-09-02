/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
// Runs the attach_fd_test fixture with the cgroup root preopened. The
// boundary checks live in the fixture; a nonzero exit code from any of them
// fails this driver.
#include "bpf-api.h"

#include <assert.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
    using namespace std;
    cout << "Performing test for `attach_fd_test.wasm`" << endl;
    ifstream module_file("../../test/wasm-apps/attach_fd_test.wasm");
    assert((bool)module_file);
    vector<uint8_t> wasm_module((istreambuf_iterator<char>(module_file)),
                                istreambuf_iterator<char>());
    // Probe natively whether this kernel and cgroup accept a sockops attach,
    // with the identical libbpf call the guest path makes. When they do, the
    // guest attach below must succeed; SKIP stays possible only when the
    // probe itself failed. Scoped so the probe's own link detaches before
    // the guest runs (safe either way: link-based cgroup attaches always
    // allow multiple programs).
    bool can_attach = false;
    {
        init_libbpf();
        wasm_bpf_program probe;
        ifstream object_file("../../test/asserts/sockops.bpf.o");
        assert((bool)object_file);
        vector<char> object((istreambuf_iterator<char>(object_file)),
                            istreambuf_iterator<char>());
        if (probe.load_bpf_object(object.data(), object.size()) >= 0) {
            can_attach = probe.attach_bpf_program("pid_tcp_opt_inject",
                                                  "/sys/fs/cgroup") == 0;
        }
    }
    cout << "native attach probe: "
         << (can_attach ? "expect-attach" : "may-skip") << endl;
    const char* args[] = {"attach_fd_test",
                          can_attach ? "expect-attach" : "may-skip"};
    const char* dirs[] = {"/sys/fs/cgroup"};
    int ret = wasm_main_ex(wasm_module.data(), (unsigned int)wasm_module.size(),
                           2, (char**)args, dirs, 1);
    cout << "exit code = " << ret << endl;
    assert(ret == 0);
    return 0;
}
