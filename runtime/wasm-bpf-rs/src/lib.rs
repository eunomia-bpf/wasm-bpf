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
use wasi_common::{
    pipe::{ReadPipe, WritePipe},
    WasiFile,
};
use wasmtime::{Engine, Linker, Module, Store};
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            callback_export_name: String::new(),
            wrapper_module_name: String::new(),
            stdin: Box::new(stdio::stdin()),
            stdout: Box::new(stdio::stdout()),
            stderr: Box::new(stdio::stderr()),
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
    ) -> Self {
        Self {
            callback_export_name,
            wrapper_module_name,
            stdin,
            stdout,
            stderr,
        }
    }
}

/// Run a Wasm eBPF module with args
pub fn run_wasm_bpf_module(
    module_binary: &[u8],
    args: &[String],
    config: Config,
) -> anyhow::Result<()> {
    let engine = Engine::default();
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

    linker
        .get(&mut store, MAIN_MODULE_NAME, "_start")
        .with_context(|| anyhow!("Failed to get _start function"))?
        .into_func()
        .with_context(|| anyhow!("Failed to cast to func"))?
        .typed::<(), ()>(&mut store)?
        .call(&mut store, ())?;
    return Ok(());
}

#[cfg(test)]
mod tests {}
