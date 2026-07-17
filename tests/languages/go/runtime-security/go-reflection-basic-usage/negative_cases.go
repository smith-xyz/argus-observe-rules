package goreflectionbasic

type Person struct {
	Name string
}

func noReflection() {
	p := Person{Name: "alice"}
	_ = p.Name
}
