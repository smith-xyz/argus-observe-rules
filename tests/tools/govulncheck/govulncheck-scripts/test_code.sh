#!/usr/bin/env bash
set -euo pipefail

govulncheck ./...
go install golang.org/x/vuln/cmd/govulncheck@latest
