WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

tick.wasm: tick.c
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $<
	cp tick.wasm ..