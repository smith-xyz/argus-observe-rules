# Argus Observe Rules

**Community-driven Semgrep rules for security analysis**

A collection of static analysis security rules developed by the community. We aim to provide helpful rules with good test coverage and clear guidance.

## About

This project focuses on building useful security rules through community collaboration:

- **Community-driven** - Built by security practitioners sharing knowledge
- **Test coverage** - Rules include positive and negative test cases
- **Clear guidance** - Actionable information, not just problem detection
- **Open collaboration** - Transparent development and review process

**Observe and Empower Philosophy**
- Focus on awareness to enable informed security decisions
- Provide insights to help teams understand their codebase
- Support security governance through better visibility

## Repository Structure

```
argus-observe-rules/
├── rules/                          # Battle-tested rule definitions
│   ├── languages/
│   │   └── go/                    # Go language rules
│   │       ├── crypto/            # Cryptographic security
│   │       ├── pqc/               # PQC readiness
│   │       └── runtime-security/  # Runtime and memory safety
│   └── tools/                     # Tool-specific rules
├── tests/                          # Comprehensive test coverage
│   └── [mirrors rules/ structure]
└── cli/                           # CLI to run various commands
    └── main.py
```

## Getting Started

Our project has all of the necessary dependencies built in to use semgrep.

```bash
make install
```

You can then set your python interpreter to the virtual environment of this project.

```bash
source .venv/bin/activate
```

## Quality Standards

We aim for helpful, reliable rules through community collaboration:

### **Rule Requirements**
- Clear documentation of the security issue and remediation
- Test cases covering both positive and negative scenarios
- Community review and feedback
- Stable rule IDs and consistent behavior

### **Goals**
- Minimize false positives while catching real issues
- Provide actionable guidance for developers
- Maintain rules that work across different codebases

### **Rule Metadata**
```yaml
metadata:
  category: crypto
  cwe: "CWE-327"
  owasp: "A02:2021 – Cryptographic Failures"
  impact: "HIGH"
  remediation_effort: "LOW"
  contributed_by: "security-team-org"
  reviewed_by: ["org1", "org2", "org3"]
```

## Contributing

We welcome contributions from security practitioners and developers:

### **How to Contribute**
1. Find a security pattern that needs coverage
2. Write a rule following our standards
3. Add test cases (positive and negative scenarios)
4. Submit a pull request for community review
5. Work with reviewers to improve the rule

### **Contribution Guidelines**
- Follow our quality standards and testing requirements
- Clearly explain the security issue and how to fix it
- Include test cases that validate the rule works correctly
- Help others understand when and how to use the rule
- Responsible use of AI tools is welcomed to help with rule development and testing

## Resources

- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute quality rules

## Related Projects

- **[Semgrep](https://github.com/semgrep/semgrep)** - The static analysis engine powering these rules
- **[OWASP](https://owasp.org/)** - Security standards and best practices
- **[CWE](https://cwe.mitre.org/)** - Common weakness enumeration

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Security is a community effort.** Help us build useful security rules that make codebases safer and more secure.
