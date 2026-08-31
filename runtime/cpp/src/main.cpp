/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <signal.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>

#include "bpf-api.h"

int main(int argc, char* argv[]) {
    std::vector<const char*> dirs;
    int arg = 1;
    while (arg < argc && strcmp(argv[arg], "--dir") == 0) {
        if (arg + 1 >= argc) {
            printf("--dir needs a directory path\n");
            return -1;
        }
        dirs.push_back(argv[arg + 1]);
        arg += 2;
    }
    if (arg >= argc) {
        printf(
            "Usage: %s [--dir PATH]... <wasm file> [wasm args]\n"
            "Each --dir preopens a directory for the wasm program as an "
            "attach\n"
            "target. Arguments after the wasm file go to the wasm program.\n",
            argv[0]);
        return -1;
    }
    signal(SIGINT, [](int x) {
        std::cerr << "Ctrl C exit..." << std::endl;
        exit(0);
    });
    std::ifstream file(argv[arg]);
    std::vector<uint8_t> wasm_module((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    return wasm_main_ex(wasm_module.data(), (unsigned int)wasm_module.size(),
                        argc - arg, argv + arg, dirs.data(), (int)dirs.size());
}
