use anyhow::{anyhow, Context};
use clap::Parser;
use flexi_logger::Logger;
use log_format::my_log_format;
use state::AppState;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;

use crate::func::{
    attach::wasm_attach_bpf_program, close::wasm_close_bpf_object,
    fd_by_name::wasm_bpf_map_fd_by_name, load::wasm_load_bpf_object,
    map_operate::wasm_bpf_map_operate, poll::wasm_bpf_buffer_poll, wrapper_poll,
};

pub const MAIN_MODULE_NAME: &str = "main";
pub const POLL_WRAPPER_FUNCTION_NAME: &str = "wasm_bpf_buffer_poll";
mod func;
mod log_format;
mod state;
mod utils;

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

    let engine = Engine::default();
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |s: &mut AppState| &mut s.wasi)
        .with_context(|| anyhow!("Failed to add wasmtime_wasi to linker"))?;
    let mut args_to_wasm = args.args_to_wasm;
    args_to_wasm.insert(0, args.wasm_module_file.clone());

    let wasi = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_args()
        .with_context(|| anyhow!("Failed to build Wasi Context"))?
        .args(&args_to_wasm[..])
        .with_context(|| anyhow!("Failed to pass arguments to Wasm program"))?
        .build();
    let mut store = Store::new(&engine, AppState::new(wasi, args.callback_export_name));
    let main_module = Module::from_file(&engine, args.wasm_module_file)
        .with_context(|| anyhow!("Failed to read wasm module file"))?;

    add_bind_function!(linker, wasm_load_bpf_object)?;
    add_bind_function!(linker, wasm_close_bpf_object)?;
    add_bind_function!(linker, wasm_attach_bpf_program)?;
    add_bind_function!(linker, wasm_bpf_buffer_poll)?;
    add_bind_function!(linker, wasm_bpf_map_fd_by_name)?;
    add_bind_function!(linker, wasm_bpf_map_operate)?;

    add_bind_function_with_module_and_name!(
        linker,
        &args.wrapper_module_name,
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
