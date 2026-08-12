WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

DEL = rm -rf
SOCKOPS_DIR = ../../../../examples/sockops

cgroup_fd_attach.wasm: cgroup_fd_attach.c sockops.data.h
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $<
	cp $@ ..

# The kernel half is the one from examples/sockops. Build it there instead of repeating the
# bpftool and vmlinux rules, which need a kernel with BTF.
sockops.bpf.o:
	$(MAKE) -C $(SOCKOPS_DIR)
	cp $(SOCKOPS_DIR)/sockops.bpf.o $@

sockops.data.h: sockops.bpf.o
	$(DEL) $@
	touch $@
	echo "#ifndef _sockops_data_H" >> $@
	echo "#define _sockops_data_H" >> $@
	echo "const char* sockops_data = \"$$(cat $< | base64 -w 0)\";" >> $@
	echo "#endif" >> $@

clean:
	$(DEL) cgroup_fd_attach.wasm sockops.bpf.o sockops.data.h
