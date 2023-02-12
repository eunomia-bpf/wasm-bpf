ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ../../third_party/vmlinux/$(ARCH)/vmlinux.h
BPF_HEADERS := ../../third_party/
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(dir $(VMLINUX)) -I$(BPF_HEADERS)
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL_SRC := ../../third_party/bpftool/src
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

APP = bootstrap

.PHONY: all
all: build

.PHONY: clean
clean:
	cargo clean
	rm -rf *.o *.json *.wasm *.skel.h

# Build BPF code
%.bpf.o: %.bpf.c $(wildcard %.h) $(VMLINUX)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g $@ # strip useless DWARF info
	$(MAKE) -C btf

.PHONY: build
build: $(APP).bpf.o
	rustup target add wasm32-wasi
	cargo build --target wasm32-wasi --release
	cp target/wasm32-wasi/release/rust-bootstrap.wasm rust-bootstrap.wasm

TEST_TIME := 3
.PHONY: test
test:
	sudo timeout --preserve-status -s 2 $(TEST_TIME) ../wasm-bpf rust-bootstrap.wasm
