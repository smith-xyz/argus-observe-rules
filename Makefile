# Argus Observe Rules - Makefile
# Simple commands for development and usage

.PHONY: help install dev-install clean lint format test validate run list

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
	@echo "  clean        Clean up temporary files"
	@echo ""
	@echo "Rule Management:"
	@echo "  validate     Validate all rules with semgrep"
	@echo "  test         Run test suite against test cases"
	@echo "  list         List available rules"
	@echo ""
	@echo "Usage Examples:"
	@echo "  run DIR=<path>    Run rules against directory"
	@echo "  run DIR=<path> RULES=crypto  Run specific category"
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
	@echo "       make run DIR=/path/to/code RULES=crypto"
	@exit 1
endif
ifdef RULES
	uv run observe run $(DIR) --rules rules/languages/go/$(RULES)
else
	uv run observe run $(DIR)
endif

# Quick development workflow
dev: dev-install lint format
	@echo "Development environment ready!"

# CI/CD targets
ci-lint: install lint

ci-test: install validate test
