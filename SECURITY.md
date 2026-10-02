# Security Policy

## Supported Versions
Security updates and patches are exclusively provided for the latest major release branch (`v1.x`).

## Vulnerability Reporting
We take the security of Aegis very seriously. If you discover a security vulnerability within this project, please adhere to responsible disclosure practices and DO NOT file a public issue on GitHub.

Instead, submit your findings via email to our security team at `security@your-domain.com`. 

Our SLA for initial triage and acknowledgment is 48 hours. Following triage, we will coordinate a timeline for the patch deployment and subsequent public disclosure.

## Architectural Security Posture
- **Data Redaction**: The system enforces strict pre-processing redaction (via regex and entropy checks) to ensure IPs and potential secrets are masked before undergoing external analysis.
- **Execution Isolation**: Automated workflows and GitHub Actions are configured with the principle of least privilege, restricting token scopes solely to required write operations on Pull Requests.
- **Untrusted Input Handling**: All source code diffs processed by the agent are treated as hostile input. Strict Pydantic schema validation is enforced to mitigate prompt injection and malformed outputs.
