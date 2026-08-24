# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please report it privately and responsibly. **Do not create public GitHub issues for security vulnerabilities.**

### Reporting Protocol
- **Direct Security Contact:** Joabson Saccomani (`jsaccomani@google.com`)
- **PGP Key ID / Fingerprint:** Available upon direct request for encrypted disclosures.
- **Response Time:** Initial response within 48 business hours; critical triage within 24 hours.

### Information to Include in Your Report
To assist in rapid triage and remediation, please include:
1. **Description of Vulnerability:** Clear summary of the security weakness and its theoretical or practical impact.
2. **Steps to Reproduce:** Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
3. **Affected Components:** Specific files, endpoints, or cloud automation scripts involved.
4. **Proposed Remediation:** Recommended patch, configuration change, or architectural mitigation if available.

---

## Supported Versions & Security Maintenance

Security patches, vulnerability mitigations, and dependency updates are applied to the active branch:

| Version / Branch | Supported | Security Maintenance Level |
|---|---|---|
| `main` (v3.0+) | Yes | Active Vulnerability Patches, SAST/DAST CI & Dependency Scanning |
| `< v3.0` | No | End of Life (Upgrade to `main` required) |

---

## Security Architecture & Design Principles

The AISPR platform adheres to the **Google Secure AI Framework (SAIF)** and Cloud Security Best Practices:

1. **Zero-Trust Architecture:** By default, all administrative web endpoints require Google Cloud Identity-Aware Proxy (IAP) assertion verification (`REQUIRE_IAP=true`) or cryptographically verified OAuth2 Bearer tokens.
2. **Least Privilege Principles:** All cloud collector scripts and Terraform blueprints request strictly scoped, read-only permissions (`roles/viewer`, `roles/aiplatform.viewer`) with explicit separation of duty.
3. **Data Protection & Privacy:** No sensitive customer prompts, customer-managed encryption keys (CMEK), or proprietary model weights are logged, exfiltrated, or persisted by the discovery agents.
4. **Supply Chain Security:** Automated Software Bill of Materials (SBOM / AI-BOM) generation conforms to CycloneDX v1.6 and SLSA Level 3 supply-chain integrity baselines.
