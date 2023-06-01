# tcpconnlat

An ebpf program to print the connection latency of each TCP connection.

The user-space program was develeoped with the new `libbpf-rs`-like SDK.

This example was adapted from [bcc's tcpconnlat](https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.c)
