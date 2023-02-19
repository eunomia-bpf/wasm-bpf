package main

import (
	"bytes"
	_ "embed"
	"go_wasm/helper"
	"time"
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

//go:embed lsm.bpf.o
var obj []byte

func main() {
	var bpfObj int32 = int32(uintptr(unsafe.Pointer(&obj[0])))
	objPtr := helper.WasmLoadBpfObject(bpfObj, int32(len(obj)))
	helper.WasmAttachBpfProgram(objPtr, CString{}.new("path_rmdir").toWasmPtr(), 0)
	for {
		time.Sleep(10 * time.Second)
	}

}
