// export
package helper

//go:wasm-module wasm_bpf
//export wasm_load_bpf_object
func WasmLoadBpfObject(int32, int32) int64

//go:wasm-module wasm_bpf
//export wasm_attach_bpf_program
func WasmAttachBpfProgram(int64, int32, int32) int32
