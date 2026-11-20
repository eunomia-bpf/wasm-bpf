#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

// all lsm the hook point refer https://www.kernel.org/doc/html/v5.2/security/LSM.html
SEC("lsm/path_rmdir")
int path_rmdir(const struct path* dir, struct dentry* dentry) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    const unsigned char dir_name[] = "can_not_rm";
    char name[32];

    // Read through d_name.name rather than d_iname: the inline buffer was
    // renamed to d_shortname (and d_name moved into an anonymous union) in
    // 6.x/7.x, while qstr.name keeps the same offset in both. CO-RE cannot
    // relocate a field the running kernel does not have, so a direct
    // &d_iname[0] read fails to load on a newer kernel.
    const unsigned char *p = BPF_CORE_READ(dir, dentry, d_name.name);
    bpf_probe_read_kernel(name, sizeof(name), p);
    name[sizeof(name) - 1] = '\0';

    bpf_printk("comm %s try to rmdir %s", comm, name);

    for (int i = 0; i < sizeof(dir_name); i++) {
        if (name[i] != dir_name[i]) {
            return 0;
        }
    }

    return -1;
}
