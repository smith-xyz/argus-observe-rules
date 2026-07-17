.PHONY: security lint

security:
	gosec -quiet ./...

lint:
	go vet ./...

install-gosec:
	go install github.com/securego/gosec/v2/cmd/gosec@latest
