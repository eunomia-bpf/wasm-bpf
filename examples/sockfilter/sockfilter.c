// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include "sockfilter.skel.h"

#define SO_ATTACH_BPF		50

int main(int argc, char **argv)
{
	struct sockfilter_bpf *skel;
	int err, prog_fd, sock;

	/* Load and verify BPF programs*/
	skel = sockfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    printf("[Client] Create TCP socket\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

	/* Attach BPF program to raw socket */
	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	sleep(10);
cleanup:
	sockfilter_bpf__destroy(skel);
	return -err;
}
