build: build-rust build-cpp

build-rust:
	$(MAKE) -C runtime/cmd build
	cp ./runtime/target/release/wasm-bpf ./wasm-bpf-rs

build-cpp:
	$(MAKE) -C runtime/cpp build
	cp ./runtime/cpp/build/bin/Release/wasm-bpf .

clean:
	$(MAKE) -C examples clean
	$(MAKE) -C runtime/cpp clean
	$(MAKE) -C runtime/cmd clean
	rm -rf wasm-bpf-rs
	rm -rf wasm-bpf

install-deps: ## install deps
	apt update
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm pahole -y ## libgtest-dev

/opt/wasi-sdk:
	wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sdk-17.0-linux.tar.gz
	tar -zxf wasi-sdk-17.0-linux.tar.gz
	sudo mkdir -p /opt/wasi-sdk/ && sudo mv wasi-sdk-17.0/* /opt/wasi-sdk/

tinygo:
	wget https://github.com/tinygo-org/tinygo/releases/download/v0.27.0/tinygo_0.27.0_amd64.deb
	sudo dpkg -i tinygo_0.27.0_amd64.deb

test:
	rm -rf runtime/cpp/build
	cd runtime/cpp && mkdir build && cd build && cmake .. && make