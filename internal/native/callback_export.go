package native

/*
#include "cedar.h"
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

//export cgwGoCallback
func cgwGoCallback(id C.uintptr_t, operation C.uint32_t, data *C.uint8_t, size C.size_t) (result C.ptrdiff_t) {
	result = -1
	// No Go panic may cross the foreign call, including invalid callback identifiers.
	defer func() { _ = recover() }()
	state, ok := cgo.Handle(id).Value().(*callbackState)
	if !ok || data == nil || uint64(size) > uint64(^uint(0)>>1) {
		return
	}
	view := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))
	return C.ptrdiff_t(state.call(uint32(operation), view))
}
