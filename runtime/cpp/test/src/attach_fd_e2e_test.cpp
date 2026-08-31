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
    const char* args[] = {"attach_fd_test"};
    const char* dirs[] = {"/sys/fs/cgroup"};
    int ret = wasm_main_ex(wasm_module.data(), (unsigned int)wasm_module.size(),
                           1, (char**)args, dirs, 1);
    cout << "exit code = " << ret << endl;
    assert(ret == 0);
    return 0;
}
