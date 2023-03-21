#include <inttypes.h>
#include <assert.h>
__attribute__((import_module("host_func_test"), import_name("plus_i32")))
int32_t
plus_i32(int32_t a, int32_t b);
int main() {
    int32_t c = plus_i32(0xABCD, 0x1234);
    assert(c == 0xABCD + 0x1234);
    return 0;
}
