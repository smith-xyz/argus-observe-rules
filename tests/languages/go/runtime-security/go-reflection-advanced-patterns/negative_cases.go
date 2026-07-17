package goreflectionadvanced

type Sample struct {
	Value int
}

func noReflectionUsage() {
	obj := Sample{Value: 1}
	_ = obj.Value
}
