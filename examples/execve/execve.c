#include <stdbool.h>
#include <stdio.h>
#include "execve.skel.h"
#include "libbpf-wasm.h"
#include "execve.h"
static int handle_event(void* ctx, void* data, size_t data_sz) {
    struct comm_event* st = (struct comm_event*)data;
    printf("[%d] %s -> %s\n", st->pid, st->parent_proc,
           st->command);
    return 0;
}

int main() {
    struct execve_bpf* skel = execve_bpf__open_and_load();
    execve_bpf__attach(skel);
    struct bpf_buffer* buf =
        bpf_buffer__open(skel->maps.comm_event, handle_event, NULL);

    while (1) {
        if (bpf_buffer__poll(buf, 0) < 0)
            break;
    }
    return 0;
}