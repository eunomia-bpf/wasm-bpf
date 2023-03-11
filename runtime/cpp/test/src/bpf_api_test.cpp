/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf org
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <vector>

#include "bpf-api.h"
extern "C" {
#include <bpf/libbpf.h>
}

#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hist {
    unsigned int slots[MAX_SLOTS];
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

static int print_log2_hists(bpf_map* map) {
    int err;
    uint32_t lookup_key = -2, next_key;
    struct hist hist;
    while (!(err = bpf_map__get_next_key(map, &lookup_key, &next_key,
                                         sizeof(next_key)))) {
        err = bpf_map__lookup_elem(map, &next_key, sizeof(next_key), &hist,
                                   sizeof(hist), 0);
        if (err < 0) {
            fprintf(stderr, "failed to lookup hist: %d\n", err);
            return -1;
        }
        printf("%-8d %-8d %-8d %-8d %-8d %-8d %-8d %-8d %-8d %-8d\n", next_key,
               hist.slots[0], hist.slots[1], hist.slots[2], hist.slots[3],
               hist.slots[4], hist.slots[5], hist.slots[6], hist.slots[7],
               hist.slots[8]);
        lookup_key = next_key;
    }
    printf("err %d\n", err);

    lookup_key = -2;
    while (!(err = bpf_map__get_next_key(map, &lookup_key, &next_key,
                                         sizeof(next_key)))) {
        err = bpf_map__delete_elem(map, &next_key, sizeof(next_key), 0);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup hist : %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}

int main(int argc, char** argv) {
    init_libbpf();
    wasm_bpf_program* program = new wasm_bpf_program();
    std::ifstream runqlat("../../test/asserts/runqlat.bpf.o");
    std::vector<char> runqlat_str((std::istreambuf_iterator<char>(runqlat)),
                                  std::istreambuf_iterator<char>());
    int res = program->load_bpf_object(runqlat_str.data(), runqlat_str.size());
    if (res < 0) {
        printf("load_bpf_object failed\n");
        delete program;
        return 0;
    }
    res = program->attach_bpf_program("handle_sched_wakeup", NULL);
    if (res < 0) {
        printf("attach_bpf_program failed handle_sched_wakeup\n");
        delete program;
        return -1;
    }
    res = program->attach_bpf_program("handle_sched_wakeup_new", NULL);
    if (res < 0) {
        printf("attach_bpf_program failed\n");
        delete program;
        return -1;
    }
    res = program->attach_bpf_program("sched_switch", NULL);
    if (res < 0) {
        printf("attach_bpf_program failed\n");
        delete program;
        return -1;
    }
    struct tm* tm;
    char ts[32];
    time_t t;
    int fd = program->bpf_map_fd_by_name("hists");
    printf("fd = %d\n", fd);
    /* main: poll */
    int count = 0;
    while (count < 5) {
        sleep(1);
        printf("\n");
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-8s\n", ts);
        bpf_map* map = program->map_ptr_by_fd(fd);
        int err = print_log2_hists(map);
        if (err)
            break;
        count++;
    }
    delete program;
    return 0;
}
