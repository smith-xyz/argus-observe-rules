# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in Argus Observe Rules, please report it privately to maintain responsible disclosure.

### Preferred Method

Create a private security advisory on GitHub:
1. Go to the Security tab in this repository
2. Click "Report a vulnerability"
3. Fill out the advisory form with details

### Alternative Contact

If GitHub security advisories are not available, contact the maintainers directly with:
- Clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation if known

## Security Considerations for Rules

### Rule Security
- Avoid patterns that could expose sensitive data in logs
- Test rules against malicious code to prevent exploitation
- Ensure rules do not introduce denial of service risks

### Test Data Security
- Never include real credentials or sensitive data in test cases
- Use clearly fake/example data in test files
- Avoid patterns that could be used to extract information

## Supported Versions

Security updates are provided for:
- Latest main branch
- Current release versions

## Security Update Process

1. Vulnerability assessment and validation
2. Fix development and testing
3. Security advisory publication
4. Coordinated release with fix
5. Community notification

Thank you for helping keep Argus Observe Rules secure.
