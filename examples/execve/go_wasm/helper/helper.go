// export
package helper

//export wasm_load_bpf_object
func WasmLoadBpfObject(int32, int32) int64

//export wasm_attach_bpf_program
func WasmAttachBpfProgram(int64, int32, int32) int32

//export wasm_bpf_map_fd_by_name
func WasmBpfMapFdByName(int64, int32) int32

//export wasm_bpf_buffer_poll
func PerfBufferPoll(int64, int32, func(ctx, data, size int32) int32, int32, int32, int32, int32) int32
