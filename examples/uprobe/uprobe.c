#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include "libbpf-wasm.h"
#include "uprobe.skel.h"

int uprobe_add(int a, int b){
    return a + b;
}

int uprobe_sub(int a, int b){
    return a - b;
}

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
    while (1) {
        int a = 1;
        int b = 2;
        printf("%d %d\n", uprobe_add(a, b), uprobe_sub(a, b));
        sleep(2);
    }
}