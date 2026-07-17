.PHONY: vuln security check test install-vuln scan

vuln:
	govulncheck ./...

security:
	govulncheck -test ./...

check:
	govulncheck ./...

test:
	govulncheck ./...

install-vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest

scan:
	govulncheck
