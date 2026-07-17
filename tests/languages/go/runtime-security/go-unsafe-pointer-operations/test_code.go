package gounsafepointer

import (
	"unsafe"
)

type Header struct {
	Data int
}

func unsafePointerPatterns() {
	var x int
	var h Header

	// Pattern: unsafe.Pointer - line 15
	_ = unsafe.Pointer(&x)

	// Pattern: cast through unsafe.Pointer - line 18
	_ = (*int)(unsafe.Pointer(&x))

	// Pattern: uintptr conversion - line 21
	_ = uintptr(unsafe.Pointer(&x))

	// Pattern: unsafe.Sizeof - line 24
	_ = unsafe.Sizeof(x)

	// Pattern: unsafe.Offsetof - line 27
	_ = unsafe.Offsetof(h.Data)

	ptr := unsafe.Pointer(&x)

	// Pattern: pointer arithmetic add - line 32
	_ = unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(x))

	// Pattern: pointer arithmetic subtract - line 35
	_ = unsafe.Pointer(uintptr(ptr) - unsafe.Sizeof(x))

	// Pattern: assignment with cast - line 38
	y := (*int)(unsafe.Pointer(&x))

	// Pattern: assignment unsafe.Pointer - line 41
	z := unsafe.Pointer(&h)

	_, _ = y, z
}
