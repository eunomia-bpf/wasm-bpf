.PHONY: all bootstrap runqlat
all: test


TEST_TIME := 3

# test with the files in bpf-loader
TEST_CASES_DIRS=$(shell ls -l . | grep ^d | awk '{print $$9}')
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
	cd ../runtime/rust && cargo build --release
	cp ../runtime/rust/target/release/wasm-bpf-rs wasm-bpf