#include <stdbool.h>
#include "libbpf-wasm.h"
#include "bootstrap.data.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include "base64decode.h"
#include <inttypes.h>
static int handle_event(void* ctx, void* data, size_t data_sz) {
    puts("Sleep started..");
    // Just sleep for 5 seconds
    usleep(5 * 1000000);
    puts("Sleep done");
    return 0;
}
int main(void) {
    size_t len = strlen(bootstrap_data);
    size_t out_len;
    const char* buf = (const char*)base64_decode(bootstrap_data, len, &out_len);
    uint64_t handle = wasm_load_bpf_object(buf, out_len);
    // This is only a test program, so just assert
    assert(handle != 0);
    int attach_result;
    attach_result = wasm_attach_bpf_program(handle, "handle_exec", "");
    assert(attach_result == 0);
    attach_result = wasm_attach_bpf_program(handle, "handle_exit", "");
    assert(attach_result == 0);
    int map_fd = wasm_bpf_map_fd_by_name(handle, "rb");
    assert(map_fd > 0);
    char buffer[256];
    // Infinite poll
    while (true) {
        wasm_bpf_buffer_poll(handle, map_fd, (int32_t)(&handle_event), (uint32_t)NULL, buffer,
                             sizeof(buffer), 100);
    }
}
