//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    fs::File,
    rc::Rc,
    sync::mpsc,
};

use libbpf_rs::{Link, Object, PerfBuffer, RingBuffer};
use wasmtime::Caller;
use wasmtime_wasi::WasiCtx;

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
    pub result_container: Rc<RefCell<Option<Vec<u8>>>>,
}
/// A `Program`, holding a bpf Object and a poller
pub struct WrapperObject {
    // Put Object in a Rc<RefCell<T>> to avoid holding a reference to WrapperObject
    /// The ebpf Object
    pub object: Rc<RefCell<Object>>,
    /// The poller; It will be set when the first time to call the sampling function
    pub poll_buffer: Option<PollBuffer>,
}

impl WrapperObject {
    /// Get a reference pointer to the EbpfObject
    pub fn get_object_rc(&self) -> Rc<RefCell<Object>> {
        self.object.clone()
    }
    /// Get a reference to the Object
    pub fn get_object(&self) -> Ref<Object> {
        self.object.borrow()
    }
    /// Get a mutable reference to the Object
    pub fn get_object_mut(&self) -> RefMut<Object> {
        self.object.borrow_mut()
    }
}

/// The application state
pub struct AppState {
    pub(crate) wasi: WasiCtx,
    pub(crate) next_object_id: u64,
    pub(crate) object_map: HashMap<u64, WrapperObject>,
    pub(crate) opened_files: Vec<File>,
    pub(crate) opened_links: Vec<Link>,
    pub(crate) callback_func_name: String,
    pub(crate) wrapper_called: bool,
    pub(crate) operation_rx: mpsc::Receiver<ProgramOperation>,
}

impl AppState {
    /// Create an AppState
    pub fn new(
        wasi: WasiCtx,
        callback_func_name: String,
        operation_rx: mpsc::Receiver<ProgramOperation>,
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
        }
    }
}

pub(crate) type CallerType<'a> = Caller<'a, AppState>;
