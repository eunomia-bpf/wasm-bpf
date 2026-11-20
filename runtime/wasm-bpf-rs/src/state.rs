//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    collections::HashMap,
    fs::File,
    sync::{mpsc, Arc, RwLock},
};

use libbpf_rs::{Link, Object, PerfBuffer, RingBuffer};
use wasmtime::Caller;
use wasmtime_wasi::preview1::WasiP1Ctx;

use crate::handle::ProgramOperation;

use ouroboros::self_referencing;
const FIRST_OBJECT_ID: u64 = 1;

/// The callback of a ringbuffer poller
pub type RingBufferCallback = Box<dyn Fn(&[u8]) -> i32>;
#[self_referencing(pub_extras)]
/// A helper container to hold a RingBuffer and its calback
pub struct RingBufferContainer {
    /// The callback
    pub callback_func: RingBufferCallback,
    #[borrows(callback_func)]
    #[covariant]
    /// The ringbuf
    pub ringbuf: RingBuffer<'this>,
}
/// The callback of a perfbuffer poller
pub type PerfBufferSampleCallback = Box<dyn Fn(i32, &[u8])>;
#[self_referencing(pub_extras)]
/// A helper container to hold a perfbuffer and its callback
pub struct PerfBufferContainer {
    /// The callback
    pub callback_func: PerfBufferSampleCallback,
    #[borrows(callback_func)]
    #[covariant]
    /// The perfbuffer
    pub perfbuf: PerfBuffer<'this>,
}
/// The enum to hold two kinds of poller
pub enum PollBufferImpl {
    /// The ringbuf
    RingBuf(RingBufferContainer),
    /// The perfevent
    PerfEvent(PerfBufferContainer),
}
/// The container of a poller implementation and its result container
/// The result container will be used to store the result that the sampling callback receives
/// since it's a shared Rc, so we can write the result in the callback regardless of the ownership
pub struct PollBuffer {
    /// The implementation
    pub inner: PollBufferImpl,
    /// The result container
    pub result_container: Arc<RwLock<Option<Vec<u8>>>>,
}
/// A `Program`, holding a bpf Object and a poller
pub struct WrapperObject {
    // Put Object in an Arc<RwLock<T>> to avoid holding a reference to WrapperObject
    /// The ebpf Object
    pub object: Arc<RwLock<Object>>,
    /// The poller; It will be set when the first time to call the sampling function
    pub poll_buffer: Option<PollBuffer>,
}

impl WrapperObject {
    /// Get a reference pointer to the EbpfObject
    pub fn get_object_rc(&self) -> Arc<RwLock<Object>> {
        self.object.clone()
    }
    /// Get a reference to the Object
    pub fn get_object(&self) -> std::sync::RwLockReadGuard<'_, Object> {
        self.object.read().unwrap()
    }
    /// Get a mutable reference to the Object
    pub fn get_object_mut(&self) -> std::sync::RwLockWriteGuard<'_, Object> {
        self.object.write().unwrap()
    }
}

/// The application state
pub struct AppState {
    pub(crate) wasi: WasiP1Ctx,
    pub(crate) next_object_id: u64,
    pub(crate) object_map: HashMap<u64, WrapperObject>,
    pub(crate) opened_files: Vec<File>,
    pub(crate) opened_links: Vec<Link>,
    pub(crate) callback_func_name: String,
    pub(crate) wrapper_called: bool,
    pub(crate) operation_rx: mpsc::Receiver<ProgramOperation>,
    /// Host handles for the directories the runtime preopened, keyed by the WASI file
    /// descriptor the guest sees. wasi-common 5.0.1 exposes no host descriptor for a WASI
    /// directory handle, so the mapping has to be recorded here at preopen time. Only
    /// descriptors the host itself opened appear here; anything the guest opened resolves to
    /// nothing.
    pub(crate) preopen_dirs: HashMap<u32, File>,
}

impl AppState {
    /// Create an AppState
    pub fn new(
        wasi: WasiP1Ctx,
        callback_func_name: String,
        operation_rx: mpsc::Receiver<ProgramOperation>,
        preopen_dirs: HashMap<u32, File>,
    ) -> Self {
        Self {
            wasi,
            next_object_id: FIRST_OBJECT_ID,
            object_map: HashMap::default(),
            opened_files: vec![],
            opened_links: vec![],
            callback_func_name,
            wrapper_called: false,
            operation_rx,
            preopen_dirs,
        }
    }
}

// `wasmtime-wasi` 36's `preview1::add_to_linker_sync` requires `T: Send`, and
// `AppState` holds libbpf handles (`Object`, `PerfBuffer`, `Link`) whose Rust
// wrappers are `!Send` even though the C objects they own are only ever touched
// from the thread that created them.
//
// That is exactly how this runtime uses them: a `Store<AppState>` is built and
// dropped inside one thread — `run_wasm_bpf_module_async` constructs it in the
// spawned thread and never shares it — so no libbpf handle crosses a thread
// boundary. The `Arc`s that remain (`object`, `result_container`) are shared
// between the store and the perf/ring buffer callbacks, which the same thread
// drives.
//
// Safety: every field is reachable only from the thread that owns the `Store`.
// Moving a `Store<AppState>` to another thread before use is sound because no
// libbpf handle has been used yet; after use the store is not shared.
unsafe impl Send for AppState {}

pub(crate) type CallerType<'a> = Caller<'a, AppState>;
