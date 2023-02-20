build: build-rust build-cpp

build-rust:
	$(MAKE) -C runtime/rust build
	cp ./runtime/rust/target/release/wasm-bpf-rs .

build-cpp:
	$(MAKE) -C runtime/cpp build
	cp ./runtime/cpp/build/bin/Release/wasm-bpf .

clean:
	$(MAKE) -C examples clean
	$(MAKE) -C runtime/cpp clean
	$(MAKE) -C runtime/rust clean
	rm -rf wasm-bpf-rs
	rm -rf wasm-bpf