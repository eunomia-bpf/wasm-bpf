# Build the runtime and examples

We have two types of runtime examples:

- A C/C++ runtime example, which is a minimal runtime based on WAMR. see [runtime/cpp](../runtime/cpp) for more details.
- A Rust runtime example, which is a more complex runtime based on Wasmtime. see [runtime/rust](../runtime/rust) for more details.

A new runtime is easy to implement with only a few hundred lines of code, in any language, using any wasm runtime or any ebpf user space library.

## build the Cpp minimal runtime based on WAMR

The dependencies are libbpf and wasm-micro-runtime only, they are
registered as git submodules.

```sh
git submodule update --init --recursive
cd runtime/cpp
```

### Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples,
package names may vary across distros.

On Ubuntu/Debian, you need:

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

### Build runtime as a executable tool

Run `make` in the `runtime/cpp` directory to build the runtime, which will be placed in the `build`
directory. `cmake` is required to build the runtime.

```sh
make build
```

### Build runtime as a library

```sh
make build-lib
```

You may refer to [CI](.github/workflows/c-cpp.yml) for more details on how
to build and run the examples.

## build the Rust runtime based on Wasmtime

install rust toolchain

```shell
curl https://sh.rustup.rs -sSf | sh -s
```

### Build runtime as a executable tool

Run `make` in the `runtime/rust` directory to build the runtime, which will be placed in the `target`
directory.

```sh
make build
```
