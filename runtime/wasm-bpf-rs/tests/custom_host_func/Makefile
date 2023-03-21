WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

custom_host_func.wasm: custom_host_func.c
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $<
	cp custom_host_func.wasm ..
