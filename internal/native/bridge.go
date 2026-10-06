package native

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "cedar.h"
extern ptrdiff_t cgwGoCallback(uintptr_t, uint32_t, uint8_t*, size_t);
static cgw_result cgw_go_call(uint64_t handle, const uint8_t *operation, size_t operation_len,
 const uint8_t *input, size_t input_len, uintptr_t id, size_t max_response) {
 return cgw_native_call(handle,operation,operation_len,input,input_len,id,
  id ? cgwGoCallback : NULL,max_response);
}
*/
import "C"

import (
	"context"
	"fmt"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

func checkABI() error {
	if version := uint32(C.cgw_native_abi_version()); version != ABIVersion {
		return fmt.Errorf("native: ABI version %d, want %d", version, ABIVersion)
	}
	return nil
}

func newHandle(name string) (uint64, error) {
	kind := C.uint32_t(1)
	if name == "analysis" {
		kind = 2
	}
	handle := uint64(C.cgw_native_new(kind))
	if handle == 0 {
		return 0, fmt.Errorf("native: cannot create %s state", name)
	}
	return handle, nil
}

func closeHandle(handle uint64) error {
	if status := C.cgw_native_close(C.uint64_t(handle)); status != 0 {
		return fmt.Errorf("native: close status %d", uint32(status))
	}
	return nil
}

func callHandle(ctx context.Context, handle uint64, operation string, input []byte, maxResponse uint32) ([]byte, error) {
	name := []byte(operation)
	var state *callbackState
	var callbackID cgo.Handle
	if callback := CallbackFrom(ctx); callback != nil {
		state = &callbackState{ctx: ctx, callback: callback}
		callbackID = cgo.NewHandle(state)
		defer callbackID.Delete()
	}
	result := C.cgw_go_call(C.uint64_t(handle), (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(name))), C.size_t(len(name)),
		(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(input))), C.size_t(len(input)), C.uintptr_t(callbackID), C.size_t(maxResponse))
	runtime.KeepAlive(input)
	runtime.KeepAlive(name)
	defer C.cgw_native_free(result)
	if state != nil && state.err != nil {
		return nil, state.err
	}
	if result.status > 1 {
		return nil, fmt.Errorf("native: operation status %d", uint32(result.status))
	}
	if result.data == nil || result.len == 0 || uint64(result.len) > uint64(maxResponse) {
		return nil, fmt.Errorf("native: invalid response length %d", uint64(result.len))
	}
	// The checked response length fits the Go int type on every supported 64-bit target.
	view := unsafe.Slice((*byte)(unsafe.Pointer(result.data)), int(result.len))
	return append([]byte(nil), view...), nil
}
