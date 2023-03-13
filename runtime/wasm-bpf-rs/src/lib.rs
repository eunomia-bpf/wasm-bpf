//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod func;
mod state;
mod utils;

pub mod pipe;

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

/// Run a Wasm eBPF module with args
pub fn run_wasm_bpf_module(
    module_binary: &[u8],
    args: &[String],
    config: Config,
) -> anyhow::Result<()> {
    WasmBpfModuleRunner::new(module_binary, args, config)?
        .into_engine_and_entry_func()?
        .1
        .run()
}
#[cfg(test)]
mod tests;
