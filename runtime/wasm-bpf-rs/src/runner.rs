use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::mpsc;

use anyhow::{anyhow, Context};
use wasi_common::{dir::DirCaps, file::FileCaps, I32Exit};
use wasmtime::{Engine, IntoFunc, Linker, Module, Store, TypedFunc};
// `Dir` and `sync::dir::Dir` are distinct types with the same name: the former is
// `cap_std::fs::Dir`, the latter the `WasiDir` implementation that wraps it.
use wasmtime_wasi::{
    ambient_authority, sync::dir::Dir as WasiDirImpl, Dir as CapStdDir, WasiCtx, WasiCtxBuilder,
};

use crate::add_bind_function_with_module;
use crate::bpf::attach::{wasm_attach_bpf_program, wasm_attach_bpf_program_fd};
use crate::bpf::close::wasm_close_bpf_object;
use crate::bpf::fd_by_name::wasm_bpf_map_fd_by_name;
use crate::bpf::load::wasm_load_bpf_object;
use crate::bpf::map_operate::wasm_bpf_map_operate;
use crate::bpf::poll::wasm_bpf_buffer_poll;
use crate::{
    add_bind_function, add_bind_function_with_module_and_name,
    bpf::wrapper_poll,
    handle::{ProgramOperation, WasmProgramHandle},
    state::AppState,
    Config, MAIN_MODULE_NAME, POLL_WRAPPER_FUNCTION_NAME,
};
/// This is a wrapper around the entry func of the wasi program, and the store it will use
pub struct WasmBpfEntryFuncWrapper {
    pub(crate) func: TypedFunc<(), ()>,
    pub(crate) store: Store<AppState>,
}

impl WasmBpfEntryFuncWrapper {
    /// Run the wasm program from the entry function
    pub fn run(self) -> anyhow::Result<()> {
        self.func.call(self.store, ())
    }
}
/// This struct provides ability to parse and link the input wasm module
pub struct WasmBpfModuleRunner {
    /// The engine which will be used to run the wasm bpf program
    pub engine: Engine,
    /// The store which will be used
    pub store: Store<AppState>,
    /// The linker which will be used
    pub linker: Linker<AppState>,
    operation_tx: mpsc::Sender<ProgramOperation>,
    main_module: Module,
}

impl WasmBpfModuleRunner {
    /// Create a runner.
    pub fn new(module_binary: &[u8], args: &[String], config: Config) -> anyhow::Result<Self> {
        let engine_config = wasmtime::Config::new()
            .epoch_interruption(true) // It must be enabled
            .to_owned();
        let engine = Engine::new(&engine_config)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s: &mut AppState| &mut s.wasi)
            .with_context(|| anyhow!("Failed to add wasmtime_wasi to linker"))?;

        let mut wasi = WasiCtxBuilder::new()
            .stdin(config.stdin)
            .stdout(config.stdout)
            .stderr(config.stderr)
            .args(args)
            .with_context(|| anyhow!("Failed to pass arguments to Wasm program"))?
            .build();
        let preopen_dirs = preopen_config_dirs(&mut wasi, &config.preopen_dirs)?;
        let (tx, rx) = mpsc::channel::<ProgramOperation>();
        let mut store = Store::new(
            &engine,
            AppState::new(wasi, config.callback_export_name.clone(), rx, preopen_dirs),
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
        add_bind_function!(linker, wasm_attach_bpf_program_fd)?;
        add_bind_function!(linker, wasm_bpf_buffer_poll)?;
        add_bind_function!(linker, wasm_bpf_map_fd_by_name)?;
        add_bind_function!(linker, wasm_bpf_map_operate)?;

        add_bind_function_with_module_and_name!(
            linker,
            &config.wrapper_module_name,
            wrapper_poll::bpf_buffer_poll_wrapper,
            POLL_WRAPPER_FUNCTION_NAME
        )?;
        Ok(Self {
            engine,
            store,
            linker,
            operation_tx: tx,
            main_module,
        })
    }
    /// Consume this runner, return a handle to the wasm program, which can control the pause/resume/terminate of the program
    /// and a wrapper that can start the wasm program
    /// For external controlling
    pub fn into_engine_and_entry_func(
        mut self,
    ) -> anyhow::Result<(WasmProgramHandle, WasmBpfEntryFuncWrapper)> {
        self.linker
            .module(&mut self.store, MAIN_MODULE_NAME, &self.main_module)
            .with_context(|| anyhow!("Failed to link main module"))?;

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
    /// Register a custom host function. It has the similar signature as `wasmtime::linker::Linker::func_wrap`
    pub fn register_host_function<Params, Args>(
        &mut self,
        module: &str,
        name: &str,
        func: impl IntoFunc<AppState, Params, Args>,
    ) -> anyhow::Result<()> {
        self.linker.func_wrap(module, name, func).map(|_| ())
    }
}

/// Preopen `dirs` for the guest, and return a host handle to each one, keyed by the descriptor
/// the guest will see.
///
/// Preopens have to be pushed consecutively and before anything else touches the descriptor
/// table, since wasi-libc discovers them by walking fd 3, 4, 5... until the first failure.
/// `push_dir` is `push_preopened_dir` that hands back the assigned descriptor, which is what keys
/// the host handles.
pub(crate) fn preopen_config_dirs(
    wasi: &mut WasiCtx,
    dirs: &[(PathBuf, PathBuf)],
) -> anyhow::Result<HashMap<u32, File>> {
    let mut preopen_dirs: HashMap<u32, File> = HashMap::new();
    for (host_path, guest_path) in dirs {
        let cap_dir = CapStdDir::open_ambient_dir(host_path, ambient_authority())
            .with_context(|| anyhow!("Failed to preopen host directory {:?}", host_path))?;
        // cap-std opens directories with `O_PATH` on Linux, so its descriptor cannot be reused
        // host-side; open a plain read-only handle for that. The two opens leave a TOCTOU window,
        // but both act on an operator-supplied path, the same trust level as the cgroup open in
        // `bpf::attach`.
        let host_handle = OpenOptions::new()
            .read(true)
            .open(host_path)
            .with_context(|| anyhow!("Failed to open host directory {:?}", host_path))?;
        // The guest needs the preopen only as a token to hand to wasm_attach_bpf_program_fd.
        // Preopen discovery (fd_prestat_get / fd_prestat_dir_name) is not gated on rights in
        // wasi-common, so empty capabilities keep discovery working while path_open, fd_readdir,
        // and any create or write beneath the directory fail.
        let guest_fd = wasi
            .push_dir(
                Box::new(WasiDirImpl::from_cap_std(cap_dir)),
                DirCaps::empty(),
                FileCaps::empty(),
                guest_path.clone(),
            )
            .with_context(|| anyhow!("Failed to preopen {:?} at {:?}", host_path, guest_path))?;
        preopen_dirs.insert(guest_fd, host_handle);
    }
    Ok(preopen_dirs)
}

/// A trait which will be implemented on anyhow::Error to check whether the error indicates an non-zero exit code
pub trait GetWasmExitCodeHelper {
    /// Returns `None` if the error doesn't indicate an non-zero exit code. Otherwise returns the exit code
    fn get_wasm_exit_code(&self) -> Option<i32>;
}

impl GetWasmExitCodeHelper for anyhow::Error {
    fn get_wasm_exit_code(&self) -> Option<i32> {
        for cause in self.chain() {
            if let Some(err) = cause.downcast_ref::<I32Exit>() {
                return Some(err.0);
            }
        }
        None
    }
}
