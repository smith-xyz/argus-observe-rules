package goreflectionbasic

import (
	"reflect"
)

type Person struct {
	Name string
	Age  int
}

func (p Person) Greet() string {
	return "hello"
}

func basicReflectCalls(obj Person, slice []int) {
	// Pattern: reflect.TypeOf - line 18
	_ = reflect.TypeOf(obj)

	// Pattern: reflect.ValueOf - line 21
	_ = reflect.ValueOf(obj)

	// Pattern: reflect.DeepEqual - line 24
	_ = reflect.DeepEqual(obj, Person{Name: "a"})

	// Pattern: reflect.Copy - line 27
	dst := make([]int, len(slice))
	_ = reflect.Copy(dst, slice)

	// Pattern: reflect.Swapper - line 31
	swap := reflect.Swapper(slice)
	swap(0, 1)

	// Pattern: reflect.Indirect - line 35
	_ = reflect.Indirect(reflect.ValueOf(&obj))

	// Pattern: reflect.Zero - line 38
	_ = reflect.Zero(reflect.TypeOf(obj))

	// Pattern: reflect.Append - line 41
	_ = reflect.Append(slice, reflect.ValueOf(3))

	// Pattern: reflect.AppendSlice - line 44
	_ = reflect.AppendSlice(slice, []int{4, 5})

	// Pattern: reflect.Select - line 47
	ch := make(chan int, 1)
	_ = reflect.Select([]reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}})
}

func typeOfMethods(obj Person) {
	typ := reflect.TypeOf(obj)

	// Pattern: Method - line 55
	_ = typ.Method(0)

	// Pattern: MethodByName - line 58
	_ = typ.MethodByName("Greet")

	// Pattern: NumMethod - line 61
	_ = typ.NumMethod()

	// Pattern: Field - line 64
	_ = typ.Field(0)

	// Pattern: FieldByName - line 67
	_ = typ.FieldByName("Name")

	// Pattern: NumField - line 70
	_ = typ.NumField()

	// Pattern: Kind - line 73
	_ = typ.Kind()

	// Pattern: String - line 76
	_ = typ.String()

	// Pattern: Name - line 79
	_ = typ.Name()
}

func valueOfMethods(obj Person) {
	val := reflect.ValueOf(obj)

	// Pattern: IsValid - line 86
	_ = val.IsValid()

	// Pattern: IsNil - line 89
	_ = val.IsNil()

	// Pattern: IsZero - line 92
	_ = val.IsZero()

	// Pattern: CanSet - line 95
	_ = val.CanSet()

	// Pattern: CanAddr - line 98
	_ = val.CanAddr()

	// Pattern: CanInterface - line 101
	_ = val.CanInterface()

	// Pattern: Kind - line 104
	_ = val.Kind()

	// Pattern: Type - line 107
	_ = val.Type()
}

func deferredTypeAndValue(obj Person) {
	val := reflect.ValueOf(obj)

	// Pattern: deferred IsValid - line 114
	_ = val.IsValid()

	// Pattern: deferred Kind on value - line 117
	_ = val.Kind()

	typ := reflect.TypeOf(obj)

	// Pattern: deferred Kind on type - line 122
	_ = typ.Kind()

	// Pattern: deferred Name - line 125
	_ = typ.Name()
}
