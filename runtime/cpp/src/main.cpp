/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <signal.h>

#include <cstdio>
#include <fstream>
#include <iostream>

#include "bpf-api.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <wasm file> [wasm args]\n", argv[0]);
        return -1;
    }
    signal(SIGINT, [](int x) {
        std::cerr << "Ctrl C exit..." << std::endl;
        exit(0);
    });
    std::ifstream file(argv[1]);
    std::vector<uint8_t> wasm_module((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    return wasm_main(wasm_module.data(), (unsigned int)wasm_module.size(),
                     argc - 1, argv + 1);
}
