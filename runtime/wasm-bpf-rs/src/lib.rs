//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod func;
mod state;
mod utils;

pub mod handle;
pub mod pipe;
pub mod runner;

use std::{sync::mpsc, thread::JoinHandle};

use anyhow::anyhow;
use handle::WasmProgramHandle;
use runner::WasmBpfModuleRunner;
use state::AppState;
use wasi_common::WasiFile;
use wasmtime_wasi::stdio;
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
    // Now we force epoch interruption to be enabled
}

impl Default for Config {
    fn default() -> Self {
        Self {
            callback_export_name: String::from("callback-wrapper"),
            wrapper_module_name: String::from("go-callback"),
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
    WasmBpfModuleRunner::new(module_binary, args, config)?
        .into_engine_and_entry_func()?
        .1
        .run()
}
/// Run a wasm module async
/// It returns two handles.
/// `WasmProgramHandle` provides ability to terminate, pause and resume the running wasmprogram.
/// `JoinHandle` provides ability to wait for the finish of the running wasm program
pub fn run_wasm_bpf_module_async(
    module_binary: &[u8],
    args: &[String],
    config: Config,
) -> anyhow::Result<(WasmProgramHandle, JoinHandle<anyhow::Result<()>>)> {
    let (tx, rx) = mpsc::channel::<WasmProgramHandle>();
    // We have to clone them to send them to another thread..
    let local_module_binary = module_binary.to_vec();
    let local_args = args.to_vec();
    let join_handle = std::thread::spawn(move || {
        let (wasm_handle, func_wrapper) =
            WasmBpfModuleRunner::new(&local_module_binary[..], &local_args[..], config)?
                .into_engine_and_entry_func()?;
        tx.send(wasm_handle)
            .map_err(|e| anyhow!("Failed to send: {}", e))?;
        func_wrapper.run()?;
        anyhow::Result::Ok(())
    });
    Ok((rx.recv()?, join_handle))
}

#[cfg(test)]
mod tests;
