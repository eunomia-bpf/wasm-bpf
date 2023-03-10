package main

import (
	"bytes"
	_ "embed"
	"fmt"
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

//export go-callback
func callback(ctx, data, size uint32) uint32 {
	/*
	   #define COMM_SIZE 352
	   struct comm_event {
	       int pid;
	       char parent_proc[16];
	       char command[COMM_SIZE];
	   };
	*/
	ptr := (unsafe.Pointer(uintptr(data)))
	pid := (unsafe.Slice((*int32)(ptr), 1))[0]
	byte_arr := unsafe.Slice((*byte)(ptr), size)
	parent_proc := string(byte_arr[4 : 4+16])
	command := string(byte_arr[4+16 : 4+16+352])

	fmt.Printf("[%d] %s -> %s\n", pid, parent_proc, command)
	return 0
}

func main() {
	var bpfObj int32 = int32(uintptr(unsafe.Pointer(&obj[0])))
	objPtr := helper.WasmLoadBpfObject(bpfObj, int32(len(obj)))
	helper.WasmAttachBpfProgram(objPtr, CString{}.new("sys_enter_execve").toWasmPtr(), 0)
	mapFd := helper.WasmBpfMapFdByName(objPtr, CString{}.new("comm_event").toWasmPtr())
	buf := make([]byte, 512, 512)

	for {
		helper.PerfBufferPoll(objPtr, mapFd, 0, int32(uintptr(unsafe.Pointer(&buf[0]))), int32(len(buf)), 100)
	}

}
