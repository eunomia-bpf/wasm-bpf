use log::error;

use crate::{func::EINVAL, state::CallerType};

use super::{poll::wasm_bpf_buffer_poll, BpfObjectType, WasmPointer};

pub fn bpf_buffer_poll_wrapper(
    mut caller: CallerType,
    program: BpfObjectType,
    fd: i32,
    ctx: WasmPointer,
    data: WasmPointer,
    max_size: i32,
    timeout_ms: i32,
) -> i32 {
    let callback_func_name = caller.data().callback_func_name.clone();
    caller.data_mut().wrapper_called = true;
    if let Some(export) = caller.get_export(&callback_func_name) {
        if export.into_func().is_none() {
            error!("Export {} is not func", callback_func_name);
            return EINVAL;
        }
    } else {
        error!("Callback export named {} not found", callback_func_name);
        return EINVAL;
    }
    wasm_bpf_buffer_poll(caller, program, fd, 0, ctx, data, max_size, timeout_ms)
}
