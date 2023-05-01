#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include "libbpf-wasm.h"
#include "uprobe.skel.h"

int main(int argc, char* argv[]) {
    struct uprobe_bpf* skel = NULL;
    int err;

    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = uprobe_bpf__attach(skel);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        return -1;
    }
    
    printf("Load and attach BPF uprobe successfully\n");
    while(1){
        sleep(10);
    }
}