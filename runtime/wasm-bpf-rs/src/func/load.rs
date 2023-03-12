//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use libbpf_rs::ObjectBuilder;
use log::debug;

use crate::{
    state::{CallerType, WrapperObject},
    utils::CallerUtils,
};

use super::WasmPointer;

/// load a bpf object from memory into the kernel
pub fn wasm_load_bpf_object(
    mut caller: CallerType,
    obj_buf: WasmPointer,
    obj_buf_size: u32,
) -> u64 {
    debug!("Load bpf object caller");
    let memory = caller.get_memory().expect("Expected exported `memory`");
    let mut buf = vec![0u8];
    if let Err(err) = memory.read(
        &mut caller,
        obj_buf as usize + obj_buf_size as usize - 1,
        &mut buf[..],
    ) {
        debug!(
            "Invalid pointer passed from wasm guest {}, size={}, err={}",
            obj_buf, obj_buf_size, err
        );
        return 0;
    }
    let open_object = match ObjectBuilder::default().open_memory(
        "",
        &memory.data(&mut caller)[obj_buf as usize..(obj_buf + obj_buf_size) as usize],
    ) {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to open bpf object: {}", err);
            return 0;
        }
    };
    let object = match open_object.load() {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to load bpf object: {}", err);
            return 0;
        }
    };
    let mut state = caller.data_mut();
    let next_id = state.next_object_id;
    state.next_object_id += 1;
    state.object_map.insert(
        next_id,
        WrapperObject {
            object,
            buffer: None,
        },
    );
    debug!("Load bpf object done, id={}", next_id);
    next_id
}
