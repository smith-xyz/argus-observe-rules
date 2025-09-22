# Contributing to Argus Observe Rules

Thank you for your interest in contributing to Argus Observe Rules. This document provides guidelines for contributing rules, tests, and improvements to the project.

## Getting Started

### Prerequisites

- Python 3.13 or higher
- UV package manager
- Semgrep CLI tool (for debugging outside the virtual environment)
- Git

### Setting Up Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/your-username/argus-observe-rules.git
   cd argus-observe-rules
   ```

2. Install dependencies:
   ```bash
   make install
   # or without make
   uv sync
   ```

3. Verify the CLI works:
   ```bash
   uv run observe --help
   ```

## Project Structure

```
argus-observe-rules/
├── cli/                    # CLI tool implementation
├── rules/                  # Semgrep rules organized by domain
│   ├── languages/         # Language-specific rules
│   │   └── go/            # Go language rules
│   │       ├── crypto/    # Cryptography rules
│   │       ├── pqc/       # Post-quantum cryptography rules
│   │       └── runtime-security/ # Runtime security rules
│   └── tools/             # Tool-specific rules
└── tests/                 # Test cases for rules
    └── languages/         # Mirror structure of rules/
```

## Contributing Rules

### Rule Organization

Rules are organized by domain and follow this naming convention:
- `go-<category>-<specific-issue>.yml`
- Example: `go-crypto-weak-cipher.yml`

### Rule Categories

- **crypto**: Cryptographic vulnerabilities and weak algorithms
- **injection**: SQL injection, command injection, etc.
- **pqc**: Post-quantum cryptography readiness analysis
- **runtime-security**: Runtime configuration security issues
- **tls**: TLS/SSL configuration and certificate validation

### Writing Rules

1. Create your rule file in the appropriate category directory
2. Follow the standard Semgrep rule format
3. Include proper metadata:
   ```yaml
   metadata:
     category: <category>
     cwe: <CWE-number>
     impact: <description of security impact>
   ```

4. Provide a meaningful fix suggestion:
   ```yaml
   fix: |
     Use secure configuration:
     - Replace insecure settings
     - Follow security best practices
   ```

### Rule Quality Guidelines

- Write specific patterns that minimize false positives
- Use meaningful rule IDs and messages
- Include comprehensive pattern coverage
- Avoid overly broad metavariable patterns
- Test patterns against real code examples

### Validating Rules

Before submitting, validate your rules:

```bash
# Validate syntax of all rules
uv run observe validate

# Validate specific rules
uv run observe validate -r "your-rule-pattern"
```

## Writing Tests

Every rule should have corresponding test cases to ensure accuracy and prevent regressions.

### Test Structure

For each rule `go-example-rule.yml`, create a test directory:

```
tests/languages/go/<category>/go-example-rule/
├── test_code.go      # Positive test cases (should trigger)
├── negative_cases.go # Negative test cases (should not trigger)
└── expected.yml      # Expected findings specification
```

### Test Files

#### test_code.go
Contains code examples that should trigger the rule:

```go
package main

func main() {
    // Example that should be detected - line 5
    insecureConfig := &Config{Insecure: true}

    // Another example - line 8
    if development {
        config.SkipVerification = true
    }
}
```

#### negative_cases.go
Contains secure code that should not trigger the rule:

```go
package main

func main() {
    // Secure configuration - should NOT trigger
    secureConfig := &Config{
        Verification: true,
        MinVersion: TLS12,
    }
}
```

#### expected.yml
Specifies expected findings and files with no findings:

```yaml
findings:
  - file: test_code.go
    line: 5
    message: "Insecure configuration detected"
  - file: test_code.go
    line: 9
    message: "Insecure configuration detected"

no_findings:
  - negative_cases.go
```

### Running Tests

```bash
# Test specific rule
uv run observe test go-example-rule

# Test multiple rules
uv run observe test "go-crypto.*"

# Test all rules (shows coverage gaps)
uv run observe test
```

### Test Guidelines

- Include diverse code patterns in positive tests
- Cover edge cases and variations
- Ensure negative tests use realistic secure alternatives
- Update line numbers in expected.yml if code changes
- Test both simple and complex scenarios

## Code Quality Standards

### Rule Consolidation

Before adding new rules, check for existing similar rules:

1. Search for related patterns:
   ```bash
   find rules -name "*.yml" | xargs grep -l "similar-pattern"
   ```

2. Consider consolidating redundant rules
3. Prefer specific, well-tested rules over many overlapping rules

### Pattern Best Practices

- Use specific literal values when possible: `InsecureSkipVerify: true`
- Avoid overly broad metavariables: `$CONFIG.Field = $VAR`
- Use multiline patterns for complex scenarios:
  ```yaml
  - pattern: |
      $VAR := true
      ...
      $CONFIG.Field = $VAR
  ```

### Performance Considerations

- Minimize complex regex patterns
- Use pattern-either efficiently
- Test rule performance on large codebases
- Avoid patterns that match too broadly

## Submitting Changes

### Pull Request Process

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/argus-observe-rules.git
   cd argus-observe-rules
   ```

3. Create a feature branch from main:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. Make your changes following the guidelines above
5. Add or update tests for your changes
6. Validate all rules and run tests:
   ```bash
   uv run observe validate
   uv run observe test
   ```

7. Commit your changes with a descriptive message
8. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

9. Update documentation if needed
10. Submit a pull request from your fork to the main repository with a clear description

### Pull Request Requirements

- All rules must pass validation
- All tests must pass
- New rules must include test cases
- Changes must not break existing functionality
- Follow established naming conventions

### Commit Message Format

Use clear, descriptive commit messages:

```
Add go-crypto-weak-cipher rule for DES/3DES detection

- Detects usage of DES and 3DES algorithms
- Includes comprehensive test cases
- Consolidates previous separate DES rules
```

## Documentation

### Updating Documentation

- Update README.md for CLI changes
- Document new rule categories or patterns
- Include examples in documentation

### Writing Style

- Use active voice
- Be concise and specific
- Provide code examples where helpful
- Avoid technical jargon without explanation

## Getting Help

### Resources

- Check existing rules for patterns and examples
- Use the CLI help: `uv run observe --help`
- **[Semgrep CLI Documentation](https://semgrep.dev/docs/for-developers/cli/)** - Official Semgrep command-line reference
- **[Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/)** - Complete guide to writing Semgrep patterns
- Search issues for similar problems

### Questions and Support

- Open an issue for bugs or feature requests
- Ask questions in pull request discussions
- Review existing pull requests for examples

## Review Process

### What Reviewers Look For

- Rule accuracy and minimal false positives
- Comprehensive test coverage
- Proper categorization and naming
- Performance impact
- Documentation completeness

Thank you for contributing to making code security analysis more effective and accessible.
