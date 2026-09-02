/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
// Runs the hostile_init_test reactor fixture, whose constructor tries to
// reach the preopened directory while the module is still being
// instantiated. The guest turns what it saw into its exit code, so zero here
// means the probe ran and every instantiation-time access was denied.
#include "bpf-api.h"

#include <assert.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
    using namespace std;
    cout << "Performing test for `hostile_init_test.wasm`" << endl;
    ifstream module_file("../../test/wasm-apps/hostile_init_test.wasm");
    assert((bool)module_file);
    vector<uint8_t> wasm_module((istreambuf_iterator<char>(module_file)),
                                istreambuf_iterator<char>());
    const char* args[] = {"hostile_init_test"};
    const char* dirs[] = {"/sys/fs/cgroup"};
    int ret = wasm_main_ex(wasm_module.data(), (unsigned int)wasm_module.size(),
                           1, (char**)args, dirs, 1);
    cout << "exit code = " << ret << endl;
    assert(ret == 0);
    return 0;
}
