use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    slice::from_raw_parts,
};

use libbpf_rs::libbpf_sys::{
    bpf_map, bpf_map__fd, bpf_map__set_autocreate, bpf_map__set_key_size, bpf_map__set_type,
    bpf_map__set_value_size, bpf_map__type, bpf_map_type, perf_buffer, perf_buffer__free,
    perf_buffer__new, perf_buffer__poll, ring_buffer, ring_buffer__free, ring_buffer__new,
    ring_buffer__poll, BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_MAP_TYPE_RINGBUF,
};
use log::{debug, error};
use wasmtime::Val;

use crate::{
    ensure_enough_memory, ensure_program_mut_by_state,
    func::{EINVAL, ENOENT},
    state::CallerType,
    utils::{CallerUtils, FunctionQuickCall},
};

use super::{BpfObjectType, WasmPointer};

pub const PERF_BUFFER_PAGES: u64 = 64;

pub struct SampleContext {
    pub wasm_ctx: u32,
    pub store_ptr: *mut CallerType<'static>,
    pub callback_index: u32,
    pub raw_wasm_data_buffer: u32,
    pub max_size: usize,
}

impl Default for SampleContext {
    fn default() -> Self {
        Self {
            wasm_ctx: u32::default(),
            store_ptr: null_mut(),
            callback_index: u32::default(),
            raw_wasm_data_buffer: u32::default(),
            max_size: usize::default(),
        }
    }
}

pub type SampleCallbackParams = (u32, u32, u32);
pub type SampleCallbackReturn = i32;
pub type SampleCallbackWrapper = extern "C" fn(*mut c_void, *mut c_void, u64) -> i32;
extern "C" fn sample_function_wrapper(ctx: *mut c_void, data: *mut c_void, size: u64) -> i32 {
    let ctx = unsafe { &*(ctx as *mut SampleContext) };
    let caller = unsafe { &mut *ctx.store_ptr };
    let available_length = ctx.max_size.min(size as usize);
    let memory = caller.get_memory().expect("Memory must be exported");
    if let Err(e) = memory.write(&mut *caller, ctx.raw_wasm_data_buffer as usize, unsafe {
        from_raw_parts(data as *const u8, available_length)
    }) {
        error!("Failed to write wasm memory: {}", e);
        return 0;
    }
    if caller.data().wrapper_called {
        let mut result = [Val::I32(0)];
        let callback = caller.data().callback_func_name.clone();
        if let Err(err) = caller
            .get_export(&callback)
            .unwrap()
            .into_func()
            .unwrap()
            .call(
                &mut *caller,
                &[
                    // Seems that tinygo cannot produce unsigned integer types, so just let wasmtiime to perform the conversion
                    Val::I32(ctx.wasm_ctx as _),
                    Val::I32(ctx.raw_wasm_data_buffer as _),
                    Val::I32(size as _),
                ],
                &mut result,
            )
        {
            error!("Failed to call the callback through direct export: {}", err);
            return 0;
        }
    } else {
        match caller.perform_indirect_call::<SampleCallbackParams, SampleCallbackReturn>(
            ctx.callback_index,
            (ctx.wasm_ctx, ctx.raw_wasm_data_buffer, size as u32),
        ) {
            Ok(v) => {
                return v;
            }
            Err(e) => {
                error!("Failed to perform indirect call when polling: {}", e);
                return 0;
            }
        }
    }

    return 0;
}

pub fn wasm_bpf_buffer_poll(
    mut caller: CallerType,
    program: BpfObjectType,
    fd: i32,
    sample_func: WasmPointer,
    ctx: WasmPointer,
    data: WasmPointer,
    max_size: i32,
    timeout_ms: i32,
) -> i32 {
    debug!("bpf buffer poll");
    let caller_ptr = &caller as *const CallerType as *mut CallerType<'static>;
    // Ensure that there is enough memory in the wasm side
    ensure_enough_memory!(caller, data, max_size, EINVAL);
    let state = caller.data_mut();
    let map_ptr = unsafe { state.get_map_ptr_by_fd(fd) };
    let object = ensure_program_mut_by_state!(state, program);

    if object.buffer.is_none() {
        let map_ptr = match map_ptr {
            Some(v) => v,
            None => {
                debug!("Invalid map fd: {}", fd);
                return ENOENT;
            }
        };
        let mut buffer = unsafe { BpfBuffer::bpf_buffer__new(map_ptr as *mut bpf_map) };
        buffer.bpf_buffer__open(sample_function_wrapper, SampleContext::default());
        object.buffer = Some(buffer);
    }
    // modify the context we passed to bpf_buffer__open each time before we call bpf_buffer_poll
    // the callback function will be called if and only if bpf_buffer__poll is called.
    // So set the pointer to `CallerType` to the caller in the current context will work
    let buffer = object.buffer.as_mut().unwrap();
    let context = buffer.host_ctx_box.as_mut().unwrap();
    context.callback_index = sample_func;
    context.max_size = max_size as usize;
    context.raw_wasm_data_buffer = data;
    context.store_ptr = caller_ptr;
    context.wasm_ctx = ctx;
    let res = buffer.bpf_buffer__poll(timeout_ms);
    if res < 0 {
        debug!("Failed to poll: {}", res);
        return res;
    }
    return 0;
}

pub enum BufferInnerType {
    PerfBuf(*mut perf_buffer),
    RingBuffer(*mut ring_buffer),
    None,
}

impl BufferInnerType {
    pub fn inner_ptr(&self) -> *mut c_void {
        match self {
            BufferInnerType::PerfBuf(s) => *s as _,
            BufferInnerType::RingBuffer(s) => *s as _,
            BufferInnerType::None => null_mut(),
        }
    }
}

pub struct BpfBuffer {
    pub events: *mut bpf_map,
    pub inner: BufferInnerType,
    // pub host_ctx: *mut c_void,
    pub map_type: bpf_map_type,
    pub host_sample_fn: Option<SampleCallbackWrapper>,
    pub wasm_sample_fn: u32,
    pub host_ctx_box: Option<Box<SampleContext>>,
}
#[allow(non_snake_case)]
impl BpfBuffer {
    pub unsafe fn bpf_buffer__new(events: *mut bpf_map) -> Self {
        let ty = if bpf_map__type(events) == BPF_MAP_TYPE_RINGBUF {
            bpf_map__set_autocreate(events, false);
            BPF_MAP_TYPE_RINGBUF
        } else {
            bpf_map__set_type(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
            bpf_map__set_key_size(events, std::mem::size_of::<i32>() as u32);
            bpf_map__set_value_size(events, std::mem::size_of::<i32>() as u32);
            BPF_MAP_TYPE_PERF_EVENT_ARRAY
        };
        Self {
            events,
            inner: BufferInnerType::None,
            host_ctx_box: None,
            map_type: ty,
            host_sample_fn: None,
            wasm_sample_fn: 0,
        }
    }
    pub fn bpf_buffer__open(
        &mut self,
        sample_callback_wrapper: SampleCallbackWrapper,
        host_ctx: SampleContext,
    ) -> i32 {
        self.host_ctx_box = Some(Box::new(host_ctx));
        let ctx_ptr = self
            .host_ctx_box
            .as_ref()
            .map(|v| &**v as *const SampleContext as *mut c_void)
            .unwrap();
        let fd = unsafe { bpf_map__fd(self.events) };
        let inner = match self.map_type {
            BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                self.host_sample_fn = Some(sample_callback_wrapper);
                BufferInnerType::PerfBuf(unsafe {
                    perf_buffer__new(
                        fd,
                        PERF_BUFFER_PAGES as _,
                        Some(perfbuf_sample_fn),
                        None,
                        ctx_ptr,
                        null(),
                    )
                })
            }
            BPF_MAP_TYPE_RINGBUF => BufferInnerType::RingBuffer(unsafe {
                ring_buffer__new(fd, Some(sample_callback_wrapper), ctx_ptr, null())
            }),
            _ => {
                return 0;
            }
        };
        if inner.inner_ptr().is_null() {
            return -1;
        }
        self.inner = inner;
        return 0;
    }
    pub fn bpf_buffer__poll(&self, timeout_ms: i32) -> i32 {
        match self.inner {
            BufferInnerType::PerfBuf(s) => unsafe { perf_buffer__poll(s, timeout_ms) },
            BufferInnerType::RingBuffer(s) => unsafe { ring_buffer__poll(s, timeout_ms) },
            BufferInnerType::None => EINVAL,
        }
    }
}

impl Drop for BpfBuffer {
    fn drop(&mut self) {
        match self.inner {
            BufferInnerType::PerfBuf(s) => unsafe {
                perf_buffer__free(s);
            },
            BufferInnerType::RingBuffer(s) => unsafe { ring_buffer__free(s) },
            BufferInnerType::None => {}
        }
    }
}

extern "C" fn perfbuf_sample_fn(ctx: *mut c_void, _cpu: i32, data: *mut c_void, size: u32) {
    sample_function_wrapper(ctx, data, size as u64);
}
