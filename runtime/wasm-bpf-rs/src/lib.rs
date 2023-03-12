//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod func;
mod state;
mod utils;

use anyhow::{anyhow, Context};
use state::AppState;
use wasi_common::WasiFile;
use wasmtime::{Engine, Linker, Module, Store, TypedFunc};
use wasmtime_wasi::{stdio, WasiCtxBuilder};

use crate::func::{
    attach::wasm_attach_bpf_program, close::wasm_close_bpf_object,
    fd_by_name::wasm_bpf_map_fd_by_name, load::wasm_load_bpf_object,
    map_operate::wasm_bpf_map_operate, poll::wasm_bpf_buffer_poll, wrapper_poll,
};

const MAIN_MODULE_NAME: &str = "main";
const POLL_WRAPPER_FUNCTION_NAME: &str = "wasm_bpf_buffer_poll";

/// The configuration for the Wasm module.
pub struct Config {
    /// Callback export name for go sdk, for example "go-callback"
    pub callback_export_name: String,
    /// Wrapper module name for go sdk, for example "callback-wrapper"
    pub wrapper_module_name: String,
    /// stdin file for receiving data from the host
    pub stdin: Box<dyn WasiFile>,
    /// stdout file for sending data to the host
    pub stdout: Box<dyn WasiFile>,
    /// stderr file for sending error to the host
    pub stderr: Box<dyn WasiFile>,
    /// Whether enable epoch interruption
    pub enable_epoch_interruption: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            callback_export_name: String::from("callback-wrapper"),
            wrapper_module_name: String::from("go-callback"),
            stdin: Box::new(stdio::stdin()),
            stdout: Box::new(stdio::stdout()),
            stderr: Box::new(stdio::stderr()),
            enable_epoch_interruption: false,
        }
    }
}

impl Config {
    /// Set the callback values for the Wasm module.
    /// The tiny go sdk requires a wrapper module and a callback export name.
    pub fn set_callback_values(
        &mut self,
        callback_export_name: String,
        wrapper_module_name: String,
    ) {
        self.callback_export_name = callback_export_name;
        self.wrapper_module_name = wrapper_module_name;
    }
    /// Create a new Config with custom values.
    pub fn new(
        callback_export_name: String,
        wrapper_module_name: String,
        stdin: Box<dyn WasiFile>,
        stdout: Box<dyn WasiFile>,
        stderr: Box<dyn WasiFile>,
        enable_epoch_interruption: bool,
    ) -> Self {
        Self {
            callback_export_name,
            wrapper_module_name,
            stdin,
            stdout,
            stderr,
            enable_epoch_interruption,
        }
    }
    pub fn set_epoch_interruption(self, f: bool) -> Self {
        Self {
            enable_epoch_interruption: f,
            ..self
        }
    }
}

pub struct WasmBpfEntryFuncWrapper {
    pub func: TypedFunc<(), ()>,
    pub store: Store<AppState>,
}

impl WasmBpfEntryFuncWrapper {
    pub fn run(self) -> anyhow::Result<()> {
        self.func.call(self.store, ())
    }
}

pub struct WasmBpfModuleRunner {
    pub engine: Engine,
    pub store: Store<AppState>,
    pub linker: Linker<AppState>,
}

impl WasmBpfModuleRunner {
    pub fn new(module_binary: &[u8], args: &[String], config: Config) -> anyhow::Result<Self> {
        let engine_config = wasmtime::Config::new()
            .epoch_interruption(config.enable_epoch_interruption)
            .to_owned();
        let engine = Engine::new(&engine_config)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s: &mut AppState| &mut s.wasi)
            .with_context(|| anyhow!("Failed to add wasmtime_wasi to linker"))?;

        let wasi = WasiCtxBuilder::new()
            .stdin(config.stdin)
            .stdout(config.stdout)
            .stderr(config.stderr)
            .args(args)
            .with_context(|| anyhow!("Failed to pass arguments to Wasm program"))?
            .build();
        let mut store = Store::new(
            &engine,
            AppState::new(wasi, config.callback_export_name.clone()),
        );

        if config.enable_epoch_interruption {
            // Once epoch was increased, wasm program will be trapped
            store.set_epoch_deadline(1);
            store.epoch_deadline_trap();
        }
        let main_module = Module::from_binary(&engine, module_binary)
            .with_context(|| anyhow!("Failed to read wasm module file"))?;
        add_bind_function!(linker, wasm_load_bpf_object)?;
        add_bind_function!(linker, wasm_close_bpf_object)?;
        add_bind_function!(linker, wasm_attach_bpf_program)?;
        add_bind_function!(linker, wasm_bpf_buffer_poll)?;
        add_bind_function!(linker, wasm_bpf_map_fd_by_name)?;
        add_bind_function!(linker, wasm_bpf_map_operate)?;

        add_bind_function_with_module_and_name!(
            linker,
            &config.wrapper_module_name,
            wrapper_poll::bpf_buffer_poll_wrapper,
            POLL_WRAPPER_FUNCTION_NAME
        )?;
        linker
            .module(&mut store, MAIN_MODULE_NAME, &main_module)
            .with_context(|| anyhow!("Failed to link main module"))?;
        Ok(Self {
            engine,
            store,
            linker,
        })
    }
    // With this we can splite engine and function into two seperate part, and allowing functions to be passed to another thread
    pub fn into_engine_and_entry_func(
        mut self,
    ) -> anyhow::Result<(Engine, WasmBpfEntryFuncWrapper)> {
        let func = self
            .linker
            .get(&mut self.store, MAIN_MODULE_NAME, "_start")
            .with_context(|| anyhow!("Failed to get _start function"))?
            .into_func()
            .with_context(|| anyhow!("Failed to cast to func"))?
            .typed::<(), ()>(&mut self.store)?;
        Ok((
            self.engine,
            WasmBpfEntryFuncWrapper {
                func,
                store: self.store,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use wasi_common::pipe::WritePipe;

    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::thread;
    // This function is only needed when running tests, so I put it here.
    pub fn get_test_file_path(name: impl AsRef<str>) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push(name.as_ref());
        path
    }
    fn test_example(name: &str, config: Config, timeout_sec: u64) {
        // Enable epoch interruption, so the wasm program can terminate after timeout_sec seconds.
        let config = config.set_epoch_interruption(true);

        let path = get_test_file_path(name);
        let mut file = File::open(path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        let args = vec!["test".to_string()];

        let (engine, func) = WasmBpfModuleRunner::new(&buffer, &args, config)
            .unwrap()
            .into_engine_and_entry_func()
            .unwrap();
        // Run the Wasm module for 3 seconds in another thread
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(timeout_sec));
            // kill the thread
            // There will be an epoch interruption in the wasm program.
            engine.increment_epoch();
        });
        let result = func.run();
        if let Err(e) = result {
            // We can't distinguish epoch trap and other errors easily...
            println!("{}", e.to_string());
        }
    }

    #[test]
    fn test_run_tracing_wasm_bpf_module() {
        test_example("execve.wasm", Config::default(), 3);
        test_example("bootstrap.wasm", Config::default(), 3);
        test_example("opensnoop.wasm", Config::default(), 3);
        test_example("lsm.wasm", Config::default(), 3);
        test_example("rust-bootstrap.wasm", Config::default(), 3);
    }

    #[test]
    fn test_run_network_wasm_bpf_module() {
        test_example("sockfilter.wasm", Config::default(), 3);
        test_example("sockops.wasm", Config::default(), 3);
    }

    #[test]
    fn test_run_wasm_bpf_module_maps() {
        test_example("runqlat.wasm", Config::default(), 3);
    }

    #[test]
    fn test_run_wasm_bpf_module_with_callback() {
        let mut config = Config::default();
        config.set_callback_values(
            String::from("go-callback"),
            String::from("callback-wrapper"),
        );
        test_example("go-execve.wasm", config, 3);
    }

    #[test]
    fn test_receive_wasm_bpf_module_output() {
        let stdout = WritePipe::new_in_memory();
        let stderr = WritePipe::new_in_memory();
        let config = Config::new(
            String::from("go-callback"),
            String::from("callback-wrapper"),
            Box::new(stdio::stdin()),
            Box::new(stdout.clone()),
            Box::new(stderr.clone()),
            true,
        );
        test_example("execve.wasm", config, 7);
        // read from the WritePipe, and write things to stdout
        let mut stdout_cursor = stdout.try_into_inner().unwrap();
        stdout_cursor.set_position(0);
        let stdout_buf = stdout_cursor.into_inner();
        let mut stderr_cursor = stderr.try_into_inner().unwrap();
        stderr_cursor.set_position(0);
        let stderr_buf = stderr_cursor.into_inner();
        println!(
            "stdout: {} bytes received, stderr: {} bytes received",
            stdout_buf.len(),
            stderr_buf.len()
        );
        assert!(stdout_buf.len() > 0);
        std::io::stdout().write(&stdout_buf[..]).unwrap();
        std::io::stdout().write(&stderr_buf[..]).unwrap();
    }
}
