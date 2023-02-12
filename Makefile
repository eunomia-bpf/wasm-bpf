.PHONY: install coverage test docs help generate_tools build
.DEFAULT_GOAL := build

define BROWSER_PYSCRIPT
import os, webbrowser, sys

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"
INSTALL_LOCATION := ~/.local

build: ## build as a tool
	rm -rf build/
	cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -Dwasm-bpf_BUILD_EXECUTABLE=1 # -Dwasm-bpf_ENABLE_ASAN=1 
	cmake --build build --config Release 

build-lib: ## build as a library
	rm -rf build/
	cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -Dwasm-bpf_BUILD_EXECUTABLE=0 # -Dwasm-bpf_ENABLE_ASAN=1 
	cmake --build build --config Release 

build-lib: ## build as a library
	rm -rf build/
	cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -Dwasm-bpf_BUILD_EXECUTABLE=0 # -Dwasm-bpf_ENABLE_ASAN=1 
	cmake --build build --config Release 

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

install-deps: ## install deps
	apt update
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm -y ## libgtest-dev

test: ## run tests quickly with ctest
	sudo rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dwasm-bpf_ENABLE_UNIT_TESTING=1 -Dwasm-bpf_ENABLE_ASAN=1 -Dwasm-bpf_ENABLE_CODE_COVERAGE=1
	cmake --build build
	cd build/ && sudo ctest -VV

/opt/wasi-sdk:
	wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sdk-17.0-linux.tar.gz
	tar -zxf wasi-sdk-17.0-linux.tar.gz
	sudo mkdir -p /opt/wasi-sdk/ && sudo mv wasi-sdk-17.0/* /opt/wasi-sdk/

test-wasm: /opt/wasi-sdk
	cd test/wasm-apps && ./build.sh

coverage: ## check code coverage quickly GCC
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dwasm-bpf_ENABLE_CODE_COVERAGE=1
	cmake --build build --config Release
	cd build/ && ctest -C Release -VV
	cd .. && (bash -c "find . -type f -name '*.gcno' -exec gcov -pb {} +" || true)

install: ## install the package to the `INSTALL_LOCATION`
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -DCMAKE_BUILD_TYPE=Release  -Dwasm-bpf_ENABLE_UNIT_TESTING=0
	cmake --build build --config Release
	cmake --build build --target install --config Release

format: ## format the project sources
	cmake -Bbuild
	cmake --build build --target clang-format

clean: ## clean the project build files
	rm -rf build/
	rm -rf docs/
