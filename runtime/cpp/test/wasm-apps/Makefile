
DEL = rm -rf

# all: binding.wasm memory_test_1.wasm memory_test_2.wasm

MODULES = binding memory_test_1 memory_test_2

MODULE_WASM_FILES = $(foreach n, $(MODULES), $(n).wasm)

all: $(MODULE_WASM_FILES)

$(MODULE_WASM_FILES) : %.wasm : %.cpp /opt/wasi-sdk/bin/clang
	/opt/wasi-sdk/bin/clang \
	    --target=wasm32-wasi \
	    -O0 -z stack-size=4096 -Wl,--initial-memory=1048576 \
	    --sysroot=/opt/wasi-sdk/share/wasi-sysroot  \
	    -Wl,--export=all \
	    -Wl,--export=bpf_main \
	    -Wl,--export=process_event \
		-Wl,--export-table \
	    -Wl,--strip-all,--no-entry \
	    -Wl,--allow-undefined \
	    -o $@ $<

clean:
	$(DEL) *.wasm

