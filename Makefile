# Argus Observe Rules - Makefile
# Simple commands for development and usage

.PHONY: help install dev-install clean lint format format-yaml test validate run generate-config

# Default target
help:
	@echo "Argus Observe Rules - Available Commands"
	@echo "========================================"
	@echo ""
	@echo "Setup:"
	@echo "  install      Install dependencies"
	@echo "  dev-install  Install with development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  lint         Run ruff linting"
	@echo "  format       Format code with ruff"
	@echo "  format-yaml  Format YAML files (requires PATH=)"
	@echo "  clean        Clean up temporary files"
	@echo ""
	@echo "Rule Management:"
	@echo "  validate     Validate all rules with semgrep"
	@echo "  test         Run test suite against test cases (all rules)"
	@echo "  generate-config  Generate unified Semgrep config files"
	@echo ""
	@echo "Usage Examples:"
	@echo "  run DIR=<path>              Run all rules against directory"
	@echo "  run DIR=<path> PATTERN=crypto  Run rules matching pattern"
	@echo "  run DIR=<path> PATTERN=md5     Run rules matching pattern"
	@echo ""

# Installation
install:
	uv sync

dev-install:
	uv sync --group dev

# Development tools
lint:
	uv run ruff check .

format:
	uv run ruff format .

format-yaml:
ifndef PATH
	@echo "Error: PATH parameter required"
	@echo "Usage: make format-yaml PATH=configs/go-runtime-security.yml"
	@echo "       make format-yaml PATH=configs/"
	@exit 1
endif
	uv run observe format-yaml $(PATH)

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

# Rule management
validate:
	uv run observe validate

# Run rule tests
test:
	uv run observe test --all


# Usage commands with parameters
run:
ifndef DIR
	@echo "Error: DIR parameter required"
	@echo "Usage: make run DIR=/path/to/code"
	@echo "       make run DIR=/path/to/code PATTERN=crypto"
	@echo "       make run DIR=/path/to/code PATTERN=md5"
	@exit 1
endif
ifdef PATTERN
	uv run observe run $(DIR) $(PATTERN)
else
	uv run observe run $(DIR) --all
endif

# Generate config files
generate-config:
	uv run observe generate-config

# Quick development workflow
dev: dev-install lint format
	@echo "Development environment ready!"

# CI/CD targets
ci: install lint validate test
