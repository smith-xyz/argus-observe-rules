package goreflectiontypeassert

import (
	"encoding/json"
	"reflect"
)

type Handler interface {
	Handle() string
}

func directInterfaceAssertion(val reflect.Value) {
	// Pattern: Interface type assertion - line 15
	_ = val.Interface().(string)

	// Pattern: Interface() - line 18
	_ = val.Interface()
}

func switchTypeAssertion(val reflect.Value) {
	// Pattern: switch on Interface().(type) - line 23
	switch m := val.Interface().(type) {
	case string:
		_ = m
	case int:
		_ = m
	}
}

func methodInterface(obj Handler) {
	// Pattern: MethodByName Interface - line 33
	method := reflect.ValueOf(obj).MethodByName("Handle")
	_ = method.Interface()
}

func resultSliceInterface(results []reflect.Value) {
	// Pattern: results index Interface - line 40
	_ = results[0].Interface()
}

func valueIndexInterface(values []reflect.Value) {
	// Pattern: value index Interface - line 45
	_ = values[1].Interface()
}

func jsonMarshalInterface(result reflect.Value) {
	// Pattern: json.Marshal Interface - line 50
	_, _ = json.Marshal(result.Interface())
}

func jsonMarshalIndentInterface(result reflect.Value) {
	// Pattern: json.MarshalIndent Interface - line 55
	_, _ = json.MarshalIndent(result.Interface(), "", "  ")
}
