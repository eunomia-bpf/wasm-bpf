//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    slice::from_raw_parts,
};

use libbpf_rs::ibbpf_sys::{
    bpf_map, bpf_map__fd, bpf_map__set_autocreate, bpf_map__set_key_size, bpf_map__set_type,
    bpf_map__set_value_size, bpf_map__type, perf_buffer, perf_buffer__free, perf_buffer__new,
    perf_buffer__poll, ring_buffer, ring_buffer__free, ring_buffer__new, ring_buffer__poll,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_UNSPEC,
};
use log::{debug, error};
use wasmtime::Val;

use crate::{
    bpf::{EINVAL, ENOENT},
    ensure_enough_memory, ensure_program_mut_by_state,
    state::CallerType,
    utils::{CallerUtils, FunctionQuickCall},
};

use super::{BpfObjectType, WasmPointer};

/// perf buffer page numbers
pub const PERF_BUFFER_PAGES: u64 = 64;

/// Context for callback function
pub struct SampleContext {
    /// context pass from wasm
    pub wasm_ctx: u32,
    /// pointer to wasm module callback function
    pub wasm_callback_func_ptr: *mut CallerType<'static>,
    pub callback_index: u32,
    pub raw_wasm_data_buffer: u32,
    pub max_size: usize,
}

impl Default for SampleContext {
    fn default() -> Self {
        Self {
            wasm_ctx: u32::default(),
            wasm_callback_func_ptr: null_mut(),
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
    debug!("sample_function_wrapper called");
    let ctx = unsafe { &*(ctx as *mut SampleContext) };
    let caller = unsafe { &mut *ctx.wasm_callback_func_ptr };
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
            return -1;
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

    0
}

/// polling the bpf buffer
///
/// bypass the clippy check, since this is a ffi function.
#[allow(clippy::too_many_arguments)]
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
    debug!(
        "wasm_bpf_buffer_poll: program: {:?}, fd: {}, sample_func: {:?}, ctx: {:?}, data: {:?}, max_size: {}, timeout_ms: {}",
        program, fd, sample_func, ctx, data, max_size, timeout_ms);
    let caller_ptr = &caller as *const CallerType as *mut CallerType<'static>;
    // Ensure that there is enough memory in the wasm side
    ensure_enough_memory!(caller, data, max_size, EINVAL);
    let state = caller.data_mut();
    let map_ptr = state.get_map_ptr_by_fd(fd);
    let object = ensure_program_mut_by_state!(state, program);

    if object.buffer.is_none() {
        let map_ptr = match map_ptr {
            Some(v) => v,
            None => {
                debug!("Invalid map fd: {}", fd);
                return -ENOENT;
            }
        };
        let mut buffer = BpfBuffer::bpf_buffer__new(map_ptr as *mut bpf_map);
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
    context.wasm_callback_func_ptr = caller_ptr;
    context.wasm_ctx = ctx;
    let res = buffer.bpf_buffer__poll(timeout_ms);
    if res < 0 {
        debug!("Failed to poll: {}", res);
        return res;
    }
    0
}

/// support types for bpf buffer
pub enum BufferInnerType {
    /// perf buffer can be used on older kernels
    PerfBuf(*mut perf_buffer),
    /// ring buffer is a new feature in kernel 5.5
    RingBuffer(*mut ring_buffer),
    /// Unsupported
    Unsupported,
}

impl BufferInnerType {
    pub fn inner_ptr(&self) -> *mut c_void {
        match self {
            BufferInnerType::PerfBuf(s) => *s as _,
            BufferInnerType::RingBuffer(s) => *s as _,
            BufferInnerType::Unsupported => null_mut(),
        }
    }
}

/// BpfBuffer is a wrapper for perf buffer and ring buffer
/// The real buffer types depends on the inner bpf types
pub struct BpfBuffer {
    map_pointer: *mut bpf_map,
    inner: BufferInnerType,
    host_sample_fn: Option<SampleCallbackWrapper>,
    host_ctx_box: Option<Box<SampleContext>>,
}

#[allow(non_snake_case)]
impl BpfBuffer {
    /// create a new bpf buffer
    pub fn bpf_buffer__new(map: *mut bpf_map) -> Self {
        Self {
            map_pointer: map,
            inner: BufferInnerType::Unsupported,
            host_ctx_box: None,
            host_sample_fn: None,
        }
    }
    /// get the buffer type in ring buffer or perf buffer
    fn get_buffer_map_type(&self) -> u32 {
        unsafe {
            if bpf_map__type(self.map_pointer) == BPF_MAP_TYPE_RINGBUF {
                bpf_map__set_autocreate(self.map_pointer, false);
                BPF_MAP_TYPE_RINGBUF
            } else if bpf_map__type(self.map_pointer) == BPF_MAP_TYPE_PERF_EVENT_ARRAY {
                bpf_map__set_type(self.map_pointer, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
                bpf_map__set_key_size(self.map_pointer, std::mem::size_of::<i32>() as u32);
                bpf_map__set_value_size(self.map_pointer, std::mem::size_of::<i32>() as u32);
                BPF_MAP_TYPE_PERF_EVENT_ARRAY
            } else {
                BPF_MAP_TYPE_UNSPEC
            }
        }
    }
    /// open the bpf buffer
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
        let ty = self.get_buffer_map_type();
        let inner = match ty {
            BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                self.host_sample_fn = Some(sample_callback_wrapper);
                BufferInnerType::PerfBuf(unsafe {
                    perf_buffer__new(
                        bpf_map__fd(self.map_pointer),
                        PERF_BUFFER_PAGES,
                        Some(perfbuf_sample_fn),
                        None,
                        ctx_ptr,
                        null(),
                    )
                })
            }
            BPF_MAP_TYPE_RINGBUF => BufferInnerType::RingBuffer(unsafe {
                ring_buffer__new(
                    bpf_map__fd(self.map_pointer),
                    Some(sample_callback_wrapper),
                    ctx_ptr,
                    null(),
                )
            }),
            _ => {
                return -EINVAL;
            }
        };
        if inner.inner_ptr().is_null() {
            return -1;
        }
        self.inner = inner;
        0
    }

    /// polling the bpf buffer
    pub fn bpf_buffer__poll(&self, timeout_ms: i32) -> i32 {
        match self.inner {
            BufferInnerType::PerfBuf(s) => unsafe { perf_buffer__poll(s, timeout_ms) },
            BufferInnerType::RingBuffer(s) => unsafe { ring_buffer__poll(s, timeout_ms) },
            BufferInnerType::Unsupported => -EINVAL,
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
            BufferInnerType::Unsupported => {}
        }
    }
}

extern "C" fn perfbuf_sample_fn(ctx: *mut c_void, _cpu: i32, data: *mut c_void, size: u32) {
    sample_function_wrapper(ctx, data, size as u64);
}
