WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

DEL = rm -rf

FILES = abnormal_exit normal_exit long_sleep

all: $(FILES)

$(FILES) : % : %.c
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@.wasm $<
	cp $@.wasm ..

clean:
	$(DEL) *.wasm
