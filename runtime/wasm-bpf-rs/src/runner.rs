use std::sync::mpsc;

use anyhow::{anyhow, Context};
use wasmtime::{Engine, Linker, Module, Store, TypedFunc};
use wasmtime_wasi::WasiCtxBuilder;

use crate::add_bind_function_with_module;
use crate::func::attach::wasm_attach_bpf_program;
use crate::func::close::wasm_close_bpf_object;
use crate::func::fd_by_name::wasm_bpf_map_fd_by_name;
use crate::func::load::wasm_load_bpf_object;
use crate::func::map_operate::wasm_bpf_map_operate;
use crate::func::poll::wasm_bpf_buffer_poll;
use crate::{
    add_bind_function, add_bind_function_with_module_and_name,
    func::wrapper_poll,
    handle::{ProgramOperation, WasmProgramHandle},
    state::AppState,
    Config, MAIN_MODULE_NAME, POLL_WRAPPER_FUNCTION_NAME,
};

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
    operation_tx: mpsc::Sender<ProgramOperation>,
}

impl WasmBpfModuleRunner {
    pub fn new(module_binary: &[u8], args: &[String], config: Config) -> anyhow::Result<Self> {
        let engine_config = wasmtime::Config::new()
            .epoch_interruption(true) // It must be enabled
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
        let (tx, rx) = mpsc::channel::<ProgramOperation>();
        let mut store = Store::new(
            &engine,
            AppState::new(wasi, config.callback_export_name.clone(), rx),
        );

        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(move |v| {
            // There should call `unwrap`.
            match v.operation_rx.recv()? {
                ProgramOperation::Resume => Ok(1),
                ProgramOperation::Terminate => Err(anyhow!("Wasm program terminated")),
            }
        });
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
            operation_tx: tx,
        })
    }
    /// Consume this runner, return a handle to the wasm program, which can control the pause/resume/terminate of the program
    /// and a wrapper that can start the wasm program
    /// For external controlling
    pub fn into_engine_and_entry_func(
        mut self,
    ) -> anyhow::Result<(WasmProgramHandle, WasmBpfEntryFuncWrapper)> {
        let func = self
            .linker
            .get(&mut self.store, MAIN_MODULE_NAME, "_start")
            .with_context(|| anyhow!("Failed to get _start function"))?
            .into_func()
            .with_context(|| anyhow!("Failed to cast to func"))?
            .typed::<(), ()>(&mut self.store)?;
        Ok((
            WasmProgramHandle::new(self.operation_tx, self.engine),
            WasmBpfEntryFuncWrapper {
                func,
                store: self.store,
            },
        ))
    }
}
