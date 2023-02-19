package main

import (
	"bytes"
	_ "embed"
	"go_wasm/helper"
	"unsafe"
)

type CString struct {
	s []byte
}

func (c CString) new(s string) *CString {
	c.s = bytes.Join([][]byte{[]byte(s), {0}}, nil)
	return &c
}

func (c *CString) toWasmPtr() int32 {
	return int32(uintptr(unsafe.Pointer(&(c.s[0]))))

}

//go:embed execve.bpf.o
var obj []byte

func callback(ctx, data, size int32) int32 {
	println("===============")
	return 0
}

func main() {
	var bpfObj int32 = int32(uintptr(unsafe.Pointer(&obj[0])))
	objPtr := helper.WasmLoadBpfObject(bpfObj, int32(len(obj)))
	helper.WasmAttachBpfProgram(objPtr, CString{}.new("sys_enter_execve").toWasmPtr(), 0)
	mapFd := helper.WasmBpfMapFdByName(objPtr, CString{}.new("comm_event").toWasmPtr())
	buf := make([]byte, 512, 512)

	for {
		helper.PerfBufferPoll(objPtr, mapFd, callback, 0, int32(uintptr(unsafe.Pointer(&buf[0]))), int32(len(buf)), 100)
	}

}
