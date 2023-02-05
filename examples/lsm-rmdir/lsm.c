#include <stdbool.h>
#include "lsm.skel.h"

int main(){
    struct lsm_bpf *obj  = lsm_bpf__open();
    lsm_bpf__load(obj);
    lsm_bpf__attach(obj);
    sleep(10000);
}
