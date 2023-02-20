use log::error;

use crate::{
    func::EINVAL,
    state::{CallerType, PollWrapper},
};

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
    let callback_func_name = match caller.data().poll_wrapper {
        PollWrapper::Disabled => {
            panic!("Something terrible happened. bpf_buffer_poll_wrapper must be called with poll_wrapper=PollWrapper::Enabled{{}}");
        }
        PollWrapper::Enabled {
            ref callback_function_name,
        } => callback_function_name.clone(),
    };
    if let Some(export) = caller.get_export(&callback_func_name) {
        // if let Some(func) = export.into_func() {
        //     if let Err(err) = func.typed::<SampleCallbackParams, SampleCallbackReturn>(&mut caller)
        //     {
        //         error!(
        //             "Invalid function signature for {}, expected func(u32, u32, u32) -> u32: {}",
        //             callback_func_name, err
        //         );
        //         return EINVAL;
        //     }
        // } else {
        //     error!("Export {} is not func", callback_func_name);
        //     return EINVAL;
        // }
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
