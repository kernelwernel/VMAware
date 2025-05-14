## Security Policy and Reporting Guidelines

Thank you for your interest in contributing to the security of **VMAware**, a C++ library for VM detection. 
We take security vulnerabilities seriously and aim to fix them promptly and responsibly. Please read and follow these guidelines when reporting a security issue.

---

### 1. Supported Versions

We only provide security fixes for the latest **v2** major release versions. 
If you discover a vulnerability in an unsupported version, please upgrade to the latest **v2.x** version and verify whether the issue still exists.

---

### 2. Reporting a Vulnerability

**Do not** open a public issue for security vulnerabilities.

1. **Contact**: Submit your report via email to the maintainers at:

   ```
   jeanruyv@gmail.com
   ```
2. **PGP Encryption**: Optionally, you can encrypt your message with our PGP key:

   ```
   -----BEGIN PGP PUBLIC KEY BLOCK-----
   Version: Keybase OpenPGP v1.0.0

   xsFNBGg... (truncated)
   -----END PGP PUBLIC KEY BLOCK-----
   ```

   * You can find the full key at [KEYS.md](https://github.com/kernelwernel/VMAware/blob/main/KEYS.md).
3. **Information to Include**:

   * A clear description of the vulnerability.
   * Steps to reproduce (proof-of-concept if available).
   * Impact assessment (what threats this poses).
   * Affected versions (as per Section 1).
   * Suggested remediation or patches if possible.

---

### 3. Triage Policy

We prioritize meaningful and actionable security vulnerabilities. Reports will be dismissed without disclosure or fix if they:

> Have minimal or no real-world impact.

> Require unrealistic or contrived conditions for exploitation.

> Are speculative, incomplete, or lack a working proof-of-concept.

> Relate to outdated or unsupported versions.

> Involve minor issues such as denial-of-service through non-production use, debug-only settings, or expected behavior in constrained environments.

We reserve the right to classify any report as non-actionable and to not disclose or acknowledge such submissions publicly.

### 4. Handling and Response Timeline

**__1.__** Acknowledgment: You will receive a response within 48 hours.

**__2.__** Evaluation: Investigation will begin within 5 business days.

**__3.__** Patch Development: If the issue is valid and severe, a fix will be developed within 30 calendar days.

**__4.__** Disclosure: For actionable vulnerabilities, we will issue a security advisory and optionally credit the reporter.

### 5. Post-Fix Actions

* The patched version will be tagged with a security banner (e.g., v2.4.0-secfix).
* We will coordinate with package repositories and downstream projects.

### 6. Summary Workflow

```text
Reporter -> jeanruyv@gmail.com (PGP optional)
    -> Maintainers ack in 48h
    -> Investigation in 5 days
    -> Patch in 30 days (if warranted)
    -> Public disclosure & credit (if warranted)
```

---

### 7. Thank You

We value community involvement and appreciate your help in improving the security of VMAware.
That said, we aim to focus our efforts on high-impact, real-world vulnerabilities that affect production use.
Your efforts help keep **VMAware** safe and reliable. We appreciate your time and expertise!
