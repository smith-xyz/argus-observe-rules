package goreflectionstructural

import (
	"reflect"
)

type Service struct {
	Name string
}

func (s Service) Run() string {
	return s.Name
}

func structuralTypeBuilders() {
	// Pattern: reflect.StructOf - line 17
	_ = reflect.StructOf([]reflect.StructField{{Name: "X", Type: reflect.TypeOf(0)}})

	// Pattern: reflect.SliceOf - line 20
	_ = reflect.SliceOf(reflect.TypeOf(0))

	// Pattern: reflect.ArrayOf - line 23
	_ = reflect.ArrayOf(3, reflect.TypeOf(0))

	// Pattern: reflect.MapOf - line 26
	_ = reflect.MapOf(reflect.TypeOf(""), reflect.TypeOf(0))

	// Pattern: reflect.PtrTo - line 29
	_ = reflect.PtrTo(reflect.TypeOf(0))

	// Pattern: reflect.ChanOf - line 32
	_ = reflect.ChanOf(reflect.BothDir, reflect.TypeOf(0))
}

func structuralValueOperations(svc Service, m map[string]int, ch chan int, slice []int) {
	val := reflect.ValueOf(svc)

	// Pattern: MethodByName - line 40
	_ = val.MethodByName("Run")

	// Pattern: FieldByName - line 43
	_ = val.FieldByName("Name")

	// Pattern: Call - line 46
	_ = val.MethodByName("Run").Call(nil)

	// Pattern: CallSlice - line 49
	_ = reflect.ValueOf(slice).CallSlice([]reflect.Value{reflect.ValueOf(1)})

	mapVal := reflect.ValueOf(m)

	// Pattern: MapIndex - line 54
	_ = mapVal.MapIndex(reflect.ValueOf("key"))

	// Pattern: SetMapIndex - line 57
	mapVal.SetMapIndex(reflect.ValueOf("key"), reflect.ValueOf(1))

	sliceVal := reflect.ValueOf(slice)

	// Pattern: Index - line 62
	_ = sliceVal.Index(0)

	// Pattern: Slice - line 65
	_ = sliceVal.Slice(0, 1)

	// Pattern: Slice3 - line 68
	_ = sliceVal.Slice3(0, 1, 2)

	chVal := reflect.ValueOf(ch)

	// Pattern: Send - line 73
	chVal.Send(reflect.ValueOf(1))

	// Pattern: Recv - line 76
	_ = chVal.Recv()

	// Pattern: TrySend - line 79
	_ = chVal.TrySend(reflect.ValueOf(2))

	// Pattern: TryRecv - line 82
	_ = chVal.TryRecv()

	// Pattern: Close - line 85
	chVal.Close()

	// Pattern: Cap - line 88
	_ = sliceVal.Cap()

	// Pattern: Len - line 91
	_ = sliceVal.Len()
}

func structuralTypeChecks(svc Service) {
	typ := reflect.TypeOf(svc)

	// Pattern: ConvertibleTo - line 99
	_ = typ.ConvertibleTo(reflect.TypeOf(Service{}))

	// Pattern: AssignableTo - line 102
	_ = typ.AssignableTo(reflect.TypeOf(Service{}))

	// Pattern: Implements - line 105
	_ = typ.Implements(reflect.TypeOf((*interface{ Run() string })(nil)).Elem())

	// Pattern: Comparable - line 108
	_ = typ.Comparable()

	// Pattern: Key - line 111
	_ = reflect.TypeOf(map[string]int{}).Key()

	// Pattern: Elem - line 114
	_ = reflect.TypeOf([]int{}).Elem()
}

func deferredStructural(svc Service, m map[string]int) {
	val := reflect.ValueOf(svc)

	// Pattern: deferred MethodByName - line 121
	_ = val.MethodByName("Run")

	// Pattern: deferred FieldByName - line 124
	_ = val.FieldByName("Name")

	// Pattern: deferred Call - line 127
	_ = val.MethodByName("Run").Call(nil)

	mapVal := reflect.ValueOf(m)

	// Pattern: deferred SetMapIndex - line 132
	mapVal.SetMapIndex(reflect.ValueOf("a"), reflect.ValueOf(1))
}

func indirectAndChained(svc Service, slice []string) {
	// Pattern: Indirect FieldByName - line 138
	_ = reflect.Indirect(reflect.ValueOf(&svc)).FieldByName("Name")

	// Pattern: Elem FieldByName - line 141
	_ = reflect.ValueOf(&svc).Elem().FieldByName("Name")

	// Pattern: Index String - line 144
	_ = reflect.ValueOf(slice).Index(0).String()

	// Pattern: FieldByName Index - line 147
	_ = reflect.ValueOf(svc).FieldByName("Name").Index(0)

	method := reflect.ValueOf(svc).MethodByName("Run")

	// Pattern: deferred Method Call - line 152
	_ = method.Call(nil)

	// Pattern: chained MethodByName Call - line 155
	_ = reflect.ValueOf(svc).MethodByName("Run").Call(nil)

	// Pattern: chained Call index - line 158
	_ = reflect.ValueOf(svc).MethodByName("Run").Call(nil)[0]

	// Pattern: chained Call Interface - line 161
	_ = reflect.ValueOf(svc).MethodByName("Run").Call(nil)[0].Interface()

	dst := reflect.ValueOf(map[string]int{})

	// Pattern: Set MakeMap - line 166
	dst.Set(reflect.MakeMap(reflect.TypeOf(map[string]int{})))

	src := reflect.ValueOf(map[string]int{"a": 1})

	// Pattern: SetMapIndex MapIndex - line 171
	dst.SetMapIndex(reflect.ValueOf("a"), src.MapIndex(reflect.ValueOf("a")))
}
