# Argus Observe Rules - Agent Guide

This repository contains Semgrep security rules organized by language and category. Rules detect security issues in codebases and provide actionable guidance.

## Repository Structure

Rules are organized in `rules/languages/{language}/{category}/` directories. Each rule file contains one or more Semgrep rules. Test cases mirror this structure in `tests/languages/{language}/{category}/{rule-id}/`.

Rule naming convention: `{language}-{category}-{specific-issue}.yml`

Categories include: crypto, pqc, runtime-security, tools

## Rule Requirements

Each rule must include:

- Clear metadata with category, CWE, impact description
- Comprehensive patterns covering variations
- Test cases in `tests/` directory with `expected.yml` specifying findings and no_findings files

Test structure:

- `test_code.{ext}` - positive test cases that should trigger
- `negative_cases.{ext}` - secure code that should not trigger
- `expected.yml` - expected findings with file and line numbers

## CLI Commands

The `observe` CLI provides rule management:

- `observe validate` - validate rule syntax
- `observe test [pattern]` - run tests against rule patterns
- `observe run <dir> [pattern]` - scan directory with rules
- `observe generate-config` - generate unified config files

Use `make` commands: `make install`, `make validate`, `make test`, `make run DIR=path`

## Code Quality Standards

- Write testable code with clear separation of concerns
- Follow code patterns appropriate for the use case
- Use active voice in documentation
- Avoid code comments unless complexity warrants explanation
- Function signatures and variable names should be self-documenting
- Do not create unnecessary scripts or extra code without consultation

## Contributing

See CONTRIBUTING.md for detailed guidelines on adding rules, writing tests, and submitting changes.

## Development Workflow

1. Install dependencies: `make install` or `uv sync`
2. Activate virtual environment: `source .venv/bin/activate`
3. Validate rules: `uv run observe validate`
4. Run tests: `uv run observe test --all`
5. Format code: `make format`
6. Lint code: `make lint`

## Key Conventions

- Rules use Semgrep YAML format with patterns, metadata, and messages
- Test expectations specify exact file and line numbers
- Patterns should minimize false positives while catching real issues
- Use specific literal values when possible, avoid overly broad metavariables
- Rules focus on security issues with clear remediation guidance
