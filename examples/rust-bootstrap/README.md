# Example: Use Rust to write user-space program

## bootstrap

This example is similar to the [bootstrap](../bootstrap) example in C/C++, but written in rust.

Just run make to build the wasm binary:

```sh
make
```

## Details for how to create a rust wasm-bpf program

### Create a Rust project 
```console
rustup target add wasm32-wasi
cargo new rust-helloworld
```

### Add `wasm-bpf-binding` as a dependency

```toml
wasm-bpf-binding = { path = "wasm-bpf-binding"}
```

This package provides bindings to functions that wasm-bpf exposed to guest programs.

### Add `wit-bindgen-guest-rust` as a dependency and patch it

```toml
[dependencies]
wit-bindgen-guest-rust = { git = "https://github.com/bytecodealliance/wit-bindgen", version = "0.3.0" }

[patch.crates-io]
wit-component = {git = "https://github.com/bytecodealliance/wasm-tools", version = "0.5.0", rev = "9640d187a73a516c42b532cf2a10ba5403df5946"}
wit-parser = {git = "https://github.com/bytecodealliance/wasm-tools", version = "0.5.0", rev = "9640d187a73a516c42b532cf2a10ba5403df5946"}
```

This package supports generating bindings for rust guest program with wit files. You don't have to run `wit-bindgen` manually.


### Generate `wit` filee using `btf2wit`

- Due to the restrictions on identifiers of WIT, you may encounter a lot of issues converting btf to wit.
- `wit-bindgen` generates strange import symbols for function whose name contains `-` (e.g, `wasm-bpf-load-object` will have an import name `wasm-bpf-load-object` but with name ``wasm_bpf_load_object``  exposed to the guest)

```sh
cd btf
clang -target bpf -g event-def.c -c -o event.def.o
btf2wit event.def.o -o event-def.wit
cp *.wit ../wit/
```

You can download the `btf2wit` tool using `cargo install btf2wit`.

### Put `wit` files under the `/wit` directory adjenct to `Cargo.toml`

Directory tree should be like:
```
Cargo.toml
src
| - main.rs
wit
| - host.wit
| - xxx.wit

....
```

`wit-bindgen-guest-rust` will generate bindings for each file in the `wit` directory. For example, a wit file:

```wit
default world host {
    record event {
         pid: s32,
        ppid: s32,
        exit-code: u32,
        --pad0: list<s8>,
        duration-ns: u64,
        comm: list<s8>,
        filename: list<s8>,
        exit-event: s8,
    }
}
```

will be converted to:

```rust
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    __pad0: [u8; 4],
    duration_ns: u64,
    comm: [u8; 16],
    filename: [u8; 127],
    exit_event: u8,
}
```

### Add `#![no_main]` attribute for `main.rs` and modify the `main` function

To adapt `wasm-bpf`, the entry point for the wasm module we wrote should be a function called `__main_argc_argv` with signature `(u32,i32)->i32`.

So modify `main` function to:

```rust
#[export_name = "__main_argc_argv"]
fn main(_env_json: u32, _str_len: i32) -> i32 {

    return 0;
}
```

### Write your program to load the bpf program and attach it

Please refer to [src/main.rs](src/main.rs). All you need to do is similar to C, for example, load and attach the eBPF program:

```rust
    let obj_ptr =
        binding::wasm_load_bpf_object(bpf_object.as_ptr() as u32, bpf_object.len() as i32);
    if obj_ptr == 0 {
        println!("Failed to load bpf object");
        return 1;
    }
    let attach_result = binding::wasm_attach_bpf_program(
        obj_ptr,
        "handle_exec\0".as_ptr() as u32,
        "\0".as_ptr() as u32,
    );
    ...
```

polling ring buffer：

```rust
    let map_fd = binding::wasm_bpf_map_fd_by_name(obj_ptr, "rb\0".as_ptr() as u32);
    if map_fd < 0 {
        println!("Failed to get map fd: {}", map_fd);
        return 1;
    }
    // binding::wasm
    let buffer = [0u8; 256];
    loop {
        // polling the buffer
        binding::wasm_bpf_buffer_poll(
            obj_ptr,
            map_fd,
            handle_event as i32,
            0,
            buffer.as_ptr() as u32,
            buffer.len() as i32,
            100,
        );
    }
```
handle the event：

```rust

extern "C" fn handle_event(_ctx: u32, data: u32, _data_sz: u32) {
    let event_slice = unsafe { slice::from_raw_parts(data as *const Event, 1) };
    let event = &event_slice[0];
    let pid = event.pid;
    let ppid = event.ppid;
    let exit_code = event.exit_code;
    if event.exit_event == 1 {
        print!(
            "{:<8} {:<5} {:<16} {:<7} {:<7} [{}]",
            "TIME",
            "EXIT",
            unsafe { CStr::from_ptr(event.comm.as_ptr() as *const i8) }
                .to_str()
                .unwrap(),
            pid,
            ppid,
            exit_code
        );
        ...
}
```

Compile and run with cargo：
```console
$ cargo build --target wasm32-wasi
```
- Note: this will produce a wasm binary that can be used to run on the current wasm-bpf (using wasm-micro-runtime, which will put all imported functions at module `$root`) 
- We are trying `wasmtime`, use `cargo build --target wasm32-wasi --features wasmtime` to produce a binary that can be used under `wasmtime`, together with `wit-bindgen` (See [https://github.com/eunomia-bpf/wasmtime-test](https://github.com/eunomia-bpf/wasmtime-test) for details)


```console
$ sudo wasm-bpf ./target/wasm32-wasi/debug/rust-helloworld.wasm
TIME     EXEC  sh               180245  33666   /bin/sh
TIME     EXEC  which            180246  180245  /usr/bin/which
TIME     EXIT  which            180246  180245  [0] (1ms)
TIME     EXIT  sh               180245  33666   [0] (3ms)
TIME     EXEC  sh               180247  33666   /bin/sh
TIME     EXEC  ps               180248  180247  /usr/bin/ps
TIME     EXIT  ps               180248  180247  [0] (23ms)
TIME     EXIT  sh               180247  33666   [0] (25ms)
TIME     EXEC  sh               180249  33666   /bin/sh
TIME     EXEC  cpuUsage.sh      180250  180249  /root/.vscode-server-insiders/bin/a7d49b0f35f50e460835a55d20a00a735d1665a3/out/vs/base/node/cpuUsage.sh
```


## Note

- Strings (e.g `&str`) are **NOT** zero-terminated. Be care when pass a pointer to foreign functions.
- Functions that be will be called by foreign code should have a signature `extern "C"` to ensure ABI.
