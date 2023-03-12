//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, Context};
use clap::Parser;
use flexi_logger::Logger;
use log_format::my_log_format;
use std::fs;
use wasm_bpf_rs::{Config, WasmBpfModuleRunner};

mod log_format;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "A WebAssembly runtime for eBPF user-space programs."
)]
struct CommandArgs {
    #[arg(help = "The WebAssembly Module file to run")]
    wasm_module_file: String,
    #[arg(long, help = "Display more logs")]
    verbose: bool,
    #[arg(short = 'm', long, help = "Wrapper module name", default_value_t = String::from("callback-wrapper"))]
    wrapper_module_name: String,
    #[arg(short = 'c', long, help = "Callback export name", default_value_t = String::from("go-callback"))]
    callback_export_name: String,
    #[arg(help = "Arguments that will be passed to the Wasm program")]
    args_to_wasm: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = CommandArgs::parse();
    Logger::try_with_str(if args.verbose { "debug" } else { "info" })?
        .format(my_log_format)
        .start()?;
    let mut args_to_wasm = args.args_to_wasm;
    args_to_wasm.insert(0, args.wasm_module_file.clone());
    let binary = fs::read(&args.wasm_module_file)
        .with_context(|| anyhow!("Failed to read wasm module file"))?;
    WasmBpfModuleRunner::new(
        &binary,
        &args_to_wasm[..],
        Config {
            callback_export_name: args.callback_export_name,
            wrapper_module_name: args.wrapper_module_name,
            ..Default::default()
        },
    )?
    .into_engine_and_entry_func()?
    .1
    .run()
}
