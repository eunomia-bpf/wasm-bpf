#include <assert.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <string>
#include "../asserts/runqlat.data.h"
#include "api.h"
#include "base64decode.h"
// char buf[1 << 20];
#define SIZE (1 << 20)
int main(int argc, char** argv) {
    using namespace std;
    size_t len = strlen(runqlat_data);
    size_t out_len;
    const char* buf = (const char*)base64_decode(runqlat_data, len, &out_len);
    uint64_t handle = wasm_load_bpf_object(buf, out_len);
    assert(handle != 0);
    char* p = (char*)malloc(SIZE);
    for (int i = 0; i < SIZE; i++)
        p[i] = 1;
    int ret = wasm_attach_bpf_program(handle, p, p);
    printf("attach ret = %d\n", ret);
    assert(ret != 0);
    return 0;
}