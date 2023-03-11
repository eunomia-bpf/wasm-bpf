#include "api.h"
#include <assert.h>
int main(int argc, char** argv) {
    int a;
    auto ret1 = wasm_load_bpf_object((const void*)(&a), 114514);
    assert(ret1 == 0);
    return 0;
}