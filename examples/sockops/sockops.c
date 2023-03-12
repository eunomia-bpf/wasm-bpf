#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include "libbpf-wasm.h"
#include "sockops.skel.h"

int main(void) {
    struct sockops_bpf* skel = NULL;
    int err;

    skel = sockops_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return -1;
    }
    bpf_set_prog_attach_target(skel->progs.pid_tcp_opt_inject,
                               "/sys/fs/cgroup/");

    err = sockops_bpf__attach(skel);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        return -1;
    }
    printf("Load and attach BPF sockops successfully\n");
    while (1) {
        sleep(10);
    }
}
