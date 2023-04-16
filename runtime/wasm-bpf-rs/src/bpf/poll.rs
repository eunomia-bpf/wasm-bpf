//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{cell::RefCell, rc::Rc, time::Duration};

use anyhow::{anyhow, Result};
use libbpf_rs::{MapType, PerfBufferBuilder, RingBufferBuilder};
use log::{debug, error};
use wasmtime::Val;

use crate::{
    bpf::{EINVAL, ENOENT},
    ensure_enough_memory, ensure_program_mut_by_caller, ensure_program_mut_by_state,
    state::{
        CallerType, PerfBufferContainerTryBuilder, PollBuffer, PollBufferImpl,
        RingBufferContainerTryBuilder,
    },
    utils::{CallerUtils, FunctionQuickCall},
};

use super::{BpfObjectType, WasmPointer};

pub type SampleCallbackParams = (u32, u32, u32);
pub type SampleCallbackReturn = i32;

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
    // Ensure that there is enough memory in the wasm side
    ensure_enough_memory!(caller, data, max_size, EINVAL);
    let object_rc = match caller.data().object_map.get(&program) {
        Some(v) => v.get_object_rc(),
        None => {
            error!("Invalid program handle: {}", program);
            return -1;
        }
    };
    let object = object_rc.borrow();
    let map = if let Some(map) = object.maps_iter().find(|v| v.fd() == fd) {
        map
    } else {
        error!("No map with fd {} found!", fd);
        return -ENOENT;
    };
    let object = ensure_program_mut_by_caller!(caller, program);
    if object.poll_buffer.is_none() {
        // Create the poller if it's not created
        let result_recv = Rc::new(RefCell::new(Some(Vec::<u8>::new())));
        let poll_impl = match map.map_type() {
            MapType::PerfEventArray => {
                let local_cb = {
                    let result_recv = result_recv.clone();
                    Box::new(move |_cpu: i32, data: &[u8]| {
                        result_recv.borrow_mut().replace(data.to_vec());
                    })
                };
                let perf_buffer = PerfBufferContainerTryBuilder {
                    callback_func: local_cb,
                    perfbuf_builder: |v| PerfBufferBuilder::new(map).sample_cb(v).build(),
                }
                .try_build();
                let perf_buffer = match perf_buffer {
                    Err(e) => {
                        error!("Failed to build perfbuffer: {}", e);
                        return 1;
                    }
                    Ok(v) => v,
                };
                PollBuffer {
                    inner: PollBufferImpl::PerfEvent(perf_buffer),
                    result_container: result_recv,
                }
            }
            MapType::RingBuf => {
                let local_cb = {
                    let result_recv = result_recv.clone();
                    Box::new(move |data: &[u8]| -> i32 {
                        result_recv.borrow_mut().replace(data.to_vec());
                        0
                    })
                };
                let ring_buffer: Result<_> = RingBufferContainerTryBuilder {
                    callback_func: local_cb,
                    ringbuf_builder: |v| {
                        let mut ringbuf = RingBufferBuilder::new();
                        ringbuf
                            .add(map, v)
                            .map_err(|e| anyhow!("Failed to add callback for ringbuf: {}", e))?;
                        ringbuf
                            .build()
                            .map_err(|e| anyhow!("Failed to build ringbuf: {}", e))
                    },
                }
                .try_build();
                let ring_buffer = match ring_buffer {
                    Err(e) => {
                        error!("Failed to build ringbuffer: {}", e);
                        return 1;
                    }
                    Ok(v) => v,
                };
                PollBuffer {
                    inner: PollBufferImpl::RingBuf(ring_buffer),
                    result_container: result_recv,
                }
            }
            s => {
                error!("Unsupported map type for polling: {}", s);
                return -1;
            }
        };
        object.poll_buffer = Some(poll_impl);
    }

    let result_container = {
        let poller = object.poll_buffer.as_ref().unwrap();
        // Clean result
        poller.result_container.borrow_mut().take();
        match &poller.inner {
            PollBufferImpl::RingBuf(rb) => {
                if let Err(e) = rb
                    .borrow_ringbuf()
                    .poll(Duration::from_millis(timeout_ms as u64))
                {
                    error!("Failed to poll ringbuf: {}", e);
                    return -1;
                }
            }
            PollBufferImpl::PerfEvent(perf) => {
                if let Err(e) = perf
                    .borrow_perfbuf()
                    .poll(Duration::from_millis(timeout_ms as u64))
                {
                    error!("Failed to poll perf event: {}", e);
                    return -1;
                }
            }
        }
        poller.result_container.clone()
    };
    // Here we could try to extract the result
    if let Some(v) = result_container.borrow_mut().take() {
        let memory = match caller.get_memory() {
            Err(e) => {
                error!("Failed to get exported memory: {}", e);
                return -1;
            }
            Ok(v) => v,
        };
        let bytes_to_write = v.len().min(max_size as usize);
        if let Err(e) = memory.write(&mut caller, data as usize, &v[..bytes_to_write]) {
            error!("Failed to write wasm memory: {}", e);
            return -1;
        }
        // Call the callback
        if caller.data().wrapper_called {
            let mut result = [Val::I32(0)];
            let callback = caller.data().callback_func_name.clone();
            if let Err(err) = caller
                .get_export(&callback)
                .unwrap()
                .into_func()
                .unwrap()
                .call(
                    &mut caller,
                    &[
                        // Seems that tinygo cannot produce unsigned integer types, so just let wasmtiime to perform the conversion
                        Val::I32(ctx as i32),
                        Val::I32(data as i32),
                        Val::I32(bytes_to_write as i32),
                    ],
                    &mut result,
                )
            {
                error!("Failed to call the callback through direct export: {}", err);
                return -1;
            }
        } else {
            match caller.perform_indirect_call::<SampleCallbackParams, SampleCallbackReturn>(
                sample_func,
                (ctx, data, bytes_to_write as u32),
            ) {
                Ok(v) => {
                    return v;
                }
                Err(e) => {
                    error!(
                        "Failed to perform indirect call when polling: {} ; {}\n{}",
                        e.to_string(),
                        e.root_cause(),
                        e.backtrace()
                    );
                    return 0;
                }
            }
        }
    }
    0
}
