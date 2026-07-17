package goreflectionstructural

type Service struct {
	Name string
}

func noStructuralReflection() {
	svc := Service{Name: "api"}
	_ = svc.Name
}
