.PHONY: all

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
THIRD_PARTY := ../../runtime/cpp/third_party

VMLINUX := $(THIRD_PARTY)/vmlinux/$(ARCH)/vmlinux.h
BPF_HEADERS := $(THIRD_PARTY)/
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(dir $(VMLINUX)) -I$(BPF_HEADERS)
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL_SRC := $(THIRD_PARTY)/bpftool/src
BPFTOOL := $(BPFTOOL_SRC)/bpftool


# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

APP = execve

.PHONY: all
all: $(APP).wasm $(APP).bpf.o

.PHONY: clean
clean:
	rm -rf *.o *.json *.wasm *.skel.h

# Build BPF code
%.bpf.o: %.bpf.c $(wildcard %.h) $(VMLINUX)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g $@ # strip useless DWARF info

# compile bpftool
$(BPFTOOL):
	cd $(BPFTOOL_SRC) && make

# generate c skeleton
%.skel.h: %.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton -j $< > $@

# generate wasm bpf header for pass struct event
$(APP).wasm.h: $(APP).bpf.o $(BPFTOOL)
	ecc $(APP).h --header-only
	$(BPFTOOL) btf dump file $< format c -j > $@

# compile for wasm with wasi-sdk
WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

$(APP).wasm: $(APP).c $(APP).skel.h
	ln -f -s ../../wasm-sdk/c/libbpf-wasm.h libbpf-wasm.h
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $< 

TEST_TIME := 3
.PHONY: test
test:
	sudo timeout -s 2 $(TEST_TIME) ../wasm-bpf $(APP).wasm || if [ $$? = 124 ]; then exit 0; else exit $$?; fi
