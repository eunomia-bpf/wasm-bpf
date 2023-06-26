#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/./target:uprobe_add")
int BPF_KPROBE(uprobe_add, int a, int b) {
    bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);
    return 0;
}

SEC("uprobe/./target:uprobe_sub")
int BPF_KPROBE(uprobe_sub, int a, int b) {
    bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
    return 0;
}