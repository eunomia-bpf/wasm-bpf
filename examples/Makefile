.PHONY: all bootstrap runqlat
all: test


TEST_TIME := 3

# The vendored libbpf and bpftool are older than the host gcc on the CI
# runners, which reports -Wdiscarded-qualifiers in libbpf's kallsyms parsing
# and turns it into an error through libbpf's own -Werror. Downgrade just that
# warning for the whole subtree, so the bootstrap of bpftool here matches what
# runtime/cpp/CMakeLists.txt already does for its own copy.
export EXTRA_CFLAGS += -Wno-error=discarded-qualifiers

# test with the files in bpf-loader
TEST_CASES_DIRS=$(shell ls -l . | grep ^d | grep -v 'go-lsm\|go-execve' | awk '{print $$9}')
test: $(TEST_CASES_DIRS)

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS): wasm-bpf
	make -C $@
	make -C $@ test

clean:
	for name in $(TEST_CASES_DIRS); do \
		$(MAKE) -C $$name clean; \
	done 
	rm -rf wasm-bpf

wasm-bpf: 
	case $$IMPL in \
		cpp) \
			make wasm-bpf-cpp \
			;; \
		rust) \
			make wasm-bpf-rs \
			;; \
		*) \
			echo "\e[31mNo runtime specified. Set env variable IMPL to either \"rust\" or \"cpp\" to specify which runtime to use\e[0m" && \
			exit 1 \
			;; \
	esac

wasm-bpf-cpp:
	make -C ../runtime/cpp 
	cp ../runtime/cpp/build/bin/Release/wasm-bpf .

wasm-bpf-rs:
	cd ../runtime/cli && cargo build --release
	cp ../runtime/target/release/wasm-bpf wasm-bpf