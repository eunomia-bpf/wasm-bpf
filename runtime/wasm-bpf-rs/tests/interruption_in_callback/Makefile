WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined,--export-table

DEL = rm -rf


interruption_in_callback.wasm: interruption_in_callback.c bootstrap.data.h
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $<
	cp $@ ..

bootstrap: bootstrap.bpf.o
	$(DEL) $@.data.h
	touch $@.data.h
	echo "#ifndef _$@_H" >> $@.data.h
	echo "#define _$@_H" >> $@.data.h
	echo "const char* $@_data = \"$$(cat $< | base64 -w 0)\";" >> $@.data.h
	echo "#endif" >> $@.data.h

bootstrap.data.h: bootstrap


clean:
	$(DEL) bootstrap.data.h
	$(DEL) *.wasm
