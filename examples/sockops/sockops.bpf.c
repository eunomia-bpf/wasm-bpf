#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);   // key always 0
  __type(value, u32); // pid
} write_pid_array SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int tp_write(struct trace_entry *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  int key = 0;
  bpf_map_update_elem(&write_pid_array, &key, &pid, 0);
  return 0;
}

static inline void set_hdr_cb_flags(struct bpf_sock_ops *skops) {
  bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
                                       BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static inline void clear_hdr_cb_flags(struct bpf_sock_ops *skops) {
  bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags &
                                       ~(BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG));
}

static inline u32 current_pid() {
  int key = 0;
  u32 *pid = bpf_map_lookup_elem(&write_pid_array, &key);
  if (!pid) {
    return 0;
  }
  return *pid;
}

struct pid_opt {
  unsigned char kind;
  unsigned char len;
  u32 pid;
} __attribute__((__packed__));

SEC("sockops")
int pid_tcp_opt_inject(struct bpf_sock_ops *skops) {

  switch (skops->op) {
  case BPF_SOCK_OPS_TCP_CONNECT_CB:
    set_hdr_cb_flags(skops);
    break;
  case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
    bpf_reserve_hdr_opt(skops, 6, 0);
    break;
  case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
    // only set in syn
    if (skops->skb_tcp_flags != 0x2) {
      return 0;
    }
    struct pid_opt opt = {
        .kind = 254,
        .len = 6,
        .pid = bpf_htonl(current_pid()),
    };

    __u16 sport, dport;
    u32 saddr, daddr;

    u16 local_port = (__u16)skops->local_port;
    u16 remote_port = bpf_ntohs(skops->remote_port >> 16);
    saddr = skops->local_ip4;
    daddr = skops->remote_ip4;

    bpf_printk("%pI4:%d -> %pI4:%d set tcp option kind: %d, pid: %d ", &saddr,
               local_port, &daddr, remote_port, 254, opt.pid);
    bpf_store_hdr_opt(skops, &opt, 6, 0);
    clear_hdr_cb_flags(skops);
    break;
  }
  }

  return 1;
}

