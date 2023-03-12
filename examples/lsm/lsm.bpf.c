#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

// all lsm the hook point refer https://www.kernel.org/doc/html/v5.2/security/LSM.html
SEC("lsm/path_rmdir")
int path_rmdir(const struct path* dir, struct dentry* dentry) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    unsigned char dir_name[] = "can_not_rm";
    unsigned char d_iname[32];
    bpf_probe_read_kernel(&d_iname[0], sizeof(d_iname),
                          &(dir->dentry->d_iname[0]));

    bpf_printk("comm %s try to rmdir %s", comm, d_iname);
    for (int i = 0; i < sizeof(dir_name); i++) {
        if (d_iname[i] != dir_name[i]) {
            return 0;
        }
    }

    return -1;
}
