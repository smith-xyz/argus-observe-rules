package goreflectionadvanced

import (
	"reflect"
	"unsafe"
)

type Sample struct {
	Value int
}

func makeOperations() {
	// Pattern: reflect.MakeFunc - line 15
	_ = reflect.MakeFunc(reflect.TypeOf(func(int) int { return 0 }), func(args []reflect.Value) []reflect.Value {
		return []reflect.Value{reflect.ValueOf(0)}
	})

	// Pattern: reflect.MakeChan - line 20
	_ = reflect.MakeChan(reflect.TypeOf(make(chan int)), 1)

	// Pattern: reflect.MakeMap - line 23
	_ = reflect.MakeMap(reflect.TypeOf(map[string]int{}))

	// Pattern: reflect.MakeMapWithSize - line 26
	_ = reflect.MakeMapWithSize(reflect.TypeOf(map[string]int{}), 4)

	// Pattern: reflect.MakeSlice - line 29
	_ = reflect.MakeSlice(reflect.TypeOf([]int{}), 2, 4)
}

func valueOperations(obj Sample) {
	// Pattern: Interface - line 34
	_ = reflect.ValueOf(obj).Interface()

	// Pattern: Convert - line 37
	_ = reflect.ValueOf(obj.Value).Convert(reflect.TypeOf(int64(0)))

	// Pattern: Elem - line 40
	ptr := &obj
	_ = reflect.ValueOf(ptr).Elem()

	// Pattern: Addr - line 44
	_ = reflect.ValueOf(obj).Addr()

	// Pattern: UnsafeAddr - line 47
	_ = reflect.ValueOf(obj).UnsafeAddr()

	// Pattern: OverflowInt - line 50
	_ = reflect.ValueOf(int8(1)).OverflowInt(128)

	// Pattern: OverflowUint - line 53
	_ = reflect.ValueOf(uint8(1)).OverflowUint(256)

	// Pattern: OverflowFloat - line 56
	_ = reflect.ValueOf(float32(1)).OverflowFloat(1e39)

	// Pattern: OverflowComplex - line 59
	_ = reflect.ValueOf(complex64(1)).OverflowComplex(complex128(1e200))
}

func deferredValueOperations(obj Sample) {
	val := reflect.ValueOf(obj)

	// Pattern: deferred Interface - line 66
	_ = val.Interface()

	// Pattern: deferred Convert - line 69
	_ = val.Convert(reflect.TypeOf(obj))

	// Pattern: deferred Addr - line 72
	_ = val.Addr()

	// Pattern: deferred UnsafeAddr - line 75
	_ = unsafe.Pointer(val.UnsafeAddr())
	_ = val.UnsafeAddr()
}
