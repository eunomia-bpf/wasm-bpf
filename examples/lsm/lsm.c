#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "lsm.skel.h"

int main(void) {
    struct lsm_bpf *skel = NULL;
    int err;

    skel = lsm_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = lsm_bpf__attach(skel);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        return -1;
    }
    printf("Load and attach BPF lsm successfully\n");
    while (1){
        sleep(10);
    }
}
