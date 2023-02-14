// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on runqlat(8) from BCC by Bredan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
// #include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include "runqlat.h"
#include "runqlat.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 1,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "runqlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize run queue (scheduler) latency as a histogram.\n"
"\n"
"USAGE: runqlat [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    runqlat         # summarize run queue latency as a histogram\n"
"    runqlat 1 10    # print 1 second summaries, 10 times\n"
"    runqlat -P      # show each PID separately\n"
"    runqlat -p 185  # trace PID 185 only\n"
"    runqlat -c CG   # Trace process under cgroupsPath CG\n";

#define OPT_PIDNSS	1	/* --pidnss */

static void
print_usage(void)
{
    printf("%s\n", argp_program_version);
    printf("%s\n", argp_program_doc);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_log2_hists(struct bpf_map *hists)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err, fd = bpf_map__fd(hists);
	uint32_t lookup_key = -2, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
		else if (env.per_pidns)
			printf("\npidns = %u %s\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct runqlat_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;
	
	// parse the args manually for demo purpose
    if (argc > 3 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage();
        return 0;
    } else if (argc == 2 && strcmp(argv[1], "-P")) {
		env.per_process = true;
	} else if (argc == 3) {
        env.interval = atoi(argv[1]);
        env.times = atoi(argv[2]);
    } else if (argc == 2) {
        env.interval = atoi(argv[1]);
    }
	if ((env.per_thread && (env.per_process || env.per_pidns)) ||
		(env.per_process && env.per_pidns)) {
		fprintf(stderr, "pidnss, pids, tids cann't be used together.\n");
		return 1;
	}

	obj = runqlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_per_pidns = env.per_pidns;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->filter_cg = env.cg;

	err = runqlat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = runqlat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(obj->maps.hists);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	runqlat_bpf__destroy(obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
