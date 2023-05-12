#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include "libbpf-wasm.h"
#include "xdp.skel.h"

int main(int argc, char* argv[]) {
    struct xdp_bpf* skel = NULL;
    int err;

    skel = xdp_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return -1;
    }
    bpf_set_prog_attach_target(skel->progs.xdp_pass, argv[1]);

    err = xdp_bpf__attach(skel);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        return -1;
    }
    printf("Load and attach BPF xdp successfully\n");
    while (1) {
        sleep(10);
    }
}
