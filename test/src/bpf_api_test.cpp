/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */

#include "bpf-api.h"
#include <fstream>
#include <vector>
#include <iostream>

int main(int argc, char **argv)
{
  init_libbpf();
  wasm_bpf_program *program = new wasm_bpf_program();
  std::ifstream runqlat("test/asserts/runqlat.o");
  std::vector<char> runqlat_str((std::istreambuf_iterator<char>(runqlat)),
                          std::istreambuf_iterator<char>());
  return 0;
}
