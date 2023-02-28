/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

typedef unsigned long long uint64_t;

struct args_t {
    const char* fname;
    int flags;
};

struct event {
    /* user terminology for pid: */
    uint64_t ts;
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    uint64_t callers[2];
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

#endif /* __OPENSNOOP_H */