struct event {
    int pid;
    int ppid;
    unsigned int exit_code;
    char __pad0[4];
    unsigned long long duration_ns;
    char comm[16];
    char filename[127];
    char exit_event;
} __attribute__((packed));

struct event* ptr;