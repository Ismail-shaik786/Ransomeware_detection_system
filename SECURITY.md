# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | ✅ Actively maintained |
| Older releases | ❌ Not supported — please upgrade |

---

## Scope

CryptLock is a **defensive, educational** ransomware detection tool.  It does
not communicate over the network, does not encrypt files, and restricts all
automated process termination to an explicit allowlist.

Relevant security concerns for this project include:

- **Path traversal** in watch-path or backup-path handling
- **Privilege escalation** via process monitoring logic
- **False-negative bypass** — inputs that cause the detector to miss a
  simulated attack that it should catch
- **Dependency vulnerabilities** in `watchdog`, `psutil`, or any other
  third-party package listed in `requirements.txt`
- **Log injection** — crafted file names that corrupt log output or reports

Out of scope:

- Theoretical attacks requiring physical access or root privilege already held
- Social engineering against end users
- Vulnerabilities in the operating system or Python runtime itself

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, send an email to:

```
ismail-shaik786@users.noreply.github.com
```

> If you prefer end-to-end encrypted communication, please mention that in your
> first message and we will arrange a PGP-encrypted channel.

### What to include

1. **Summary** — a concise description of the vulnerability
2. **Affected component** — which file / function / module
3. **Steps to reproduce** — exact commands or test case
4. **Impact** — what an attacker could achieve
5. **Suggested fix** (optional but appreciated)

### Response timeline

| Stage | Target time |
|-------|-------------|
| Acknowledgement | Within **48 hours** |
| Triage & severity assessment | Within **5 business days** |
| Fix released (for valid reports) | Within **30 days** for high/critical severity |
| Public disclosure | Coordinated with the reporter |

We follow a **responsible disclosure** model.  We will credit reporters in the
release notes unless you prefer to remain anonymous.

---

## Ethical Use Reminder

This project is released under the MIT Licence with an **additional ethical
use clause**.  Any discovered vulnerability must be reported privately — not
used to bypass the safety mechanisms of the tool or to facilitate real
ransomware attacks.  See [LICENSE](LICENSE) for details.
