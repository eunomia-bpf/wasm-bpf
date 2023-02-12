.PHONY: all bootstrap runqlat
all: test

clean:
	$(MAKE) -C bootstrap clean
	$(MAKE) -C runqlat clean
	$(MAKE) -C sockfilter clean

TEST_TIME := 3

# test with the files in bpf-loader
TEST_CASES_DIRS=$(shell ls -l . | grep ^d | awk '{print $$9}')
test: $(TEST_CASES_DIRS)

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS):
	cp ../build/bin/Release/wasm-bpf .
	make -C $@
	make -C $@ test
