# Argus Observe Rules

**Community-driven, battle-tested Semgrep rules for production codebases**

A collaborative collection of high-quality static analysis security rules with comprehensive test coverage and rigorous quality standards. Built by security practitioners, for security practitioners - from individual developers to large organizations.

## Why Argus Observe Rules?

**Battle-Tested Quality**
- **Comprehensive Testing** - Every rule includes positive/negative test cases
- **Low False Positives** - Extensively tuned for real-world codebases
- **Clear Remediation** - Actionable fix guidance, not just problem detection
- **Production Validated** - Rules tested against diverse, real-world projects

**Community-Driven Excellence**
- **Open Collaboration** - Built by security practitioners worldwide
- **Transparent Quality** - Open metrics and confidence scoring
- **Continuous Improvement** - Regular updates based on community feedback
- **Peer Review** - Multiple security teams validate each rule

**Observe and Empower Philosophy**
- **Awareness-Focused** - Observe patterns to enable informed decisions
- **Non-Judgmental** - Provide insights without criticism
- **Team Empowerment** - Give organizations the awareness they need to act
- **Governance Through Insight** - Like Argus with hundred eyes, always watching to help

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

**Community-maintained quality ensures production readiness:**

### **Accuracy Requirements**
- **≥95% Precision** - Minimal false positives across diverse codebases
- **≥90% Recall** - Comprehensive coverage of vulnerability patterns
- **Real-world Validation** - Tested by multiple organizations and projects

### **Contribution Standards**
- **Clear Documentation** - Understandable impact and remediation guidance
- **Comprehensive Tests** - Both positive and negative test cases required
- **Peer Review** - Community validation before acceptance
- **Backwards Compatibility** - Stable rule IDs and behavior

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

## Community & Contributions

### **Open Collaboration**
- **Anyone Can Contribute** - Individuals, teams, organizations welcome
- **Transparent Process** - Open review and discussion for all contributions
- **Diverse Perspectives** - Rules validated across different environments
- **Knowledge Sharing** - Learn from security practitioners worldwide

### **How to Contribute**
1. **Identify Need** - Find a security pattern not currently covered
2. **Write Rule** - Follow our quality standards and testing requirements
3. **Add Tests** - Include comprehensive positive/negative test cases
4. **Submit PR** - Community review and validation process
5. **Iterate** - Collaborate with reviewers to refine quality

### **Contribution Guidelines**
- **Quality First** - Rules must meet accuracy and testing standards
- **Clear Communication** - Explain the security impact and fix guidance
- **Test Coverage** - Validate against real-world code patterns
- **Documentation** - Help others understand and use your rules

## Resources

- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute quality rules

## Related Projects

- **[Semgrep](https://github.com/semgrep/semgrep)** - The static analysis engine powering these rules
- **[OWASP](https://owasp.org/)** - Security standards and best practices
- **[CWE](https://cwe.mitre.org/)** - Common weakness enumeration

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Security is a community effort.** Join security practitioners worldwide in building the most comprehensive, battle-tested collection of security rules for modern development.
