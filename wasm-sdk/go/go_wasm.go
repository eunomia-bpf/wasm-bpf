//go:build js,wasm
// +build js,wasm

// export
package helper

//go:wasm-module wasm_bpf
//export wasm_bpf_map_operate
func WasmBpfMapOperate(int32, int32, int64, int64, int64, int64) int32

//go:wasm-module callback-wrapper
//export wasm_bpf_buffer_poll
func PerfBufferPoll(int64, int32, int32, int32, int32, int32) int32

//go:wasm-module wasm_bpf
//export wasm_attach_bpf_program
func WasmAttachBpfProgram(int64, int32, int32) int32

//go:wasm-module wasm_bpf
//export wasm_load_bpf_object
func WasmLoadBpfObject(int32, int32) int64

//go:wasm-module wasm_bpf
//export wasm_close_bpf_object
func WasmCloseBpfObject(int64) int32

//go:wasm-module wasm_bpf
//export wasm_bpf_map_fd_by_name
func WasmBpfMapFdByName(int64, int32) int32






