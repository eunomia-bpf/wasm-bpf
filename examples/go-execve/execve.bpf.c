#include "execve.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[4] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} comm_event SEC(".maps");

struct execve_args {
    struct trace_entry common;
    int unused;
    char* file;
    char* const* argv;
    char* const* envp;
};

SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct execve_args* ctx) {
    struct comm_event comm;
    comm.pid = (int)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    bpf_get_current_comm(&(comm.parent_proc[0]), sizeof(comm.parent_proc));

    __builtin_memset(&(comm.command[0]), 0, sizeof(comm.command));
    int start = 0;
    int end = COMM_SIZE - 1;

    char* args[MAX_ARG_NUM];
    int idx = 0;
    for (; idx < MAX_ARG_NUM; idx++) {
        if (bpf_probe_read_user(&args[idx], sizeof(args[idx]),
                                &ctx->argv[idx]) != 0)
            break;
    }

    for (int i = 0; i < idx && start < end; i++) {
        long n =
            bpf_probe_read_user_str(&comm.command[start], ARG_LEN, args[i]);
        if (n <= 0) {
            break;
        }
        start += (int)(n);
        comm.command[start - 1] = ' ';
    }
    if (start < end) {
        comm.command[start] = 0;
    }

    bpf_printk("pid: %d, proc: %s, execve:  %s", comm.pid, comm.parent_proc,
               comm.command);

    bpf_ringbuf_output(&comm_event, &comm, sizeof(struct comm_event), 0);

    return 0;
}