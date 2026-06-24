# Contributing to CryptLock

Thank you for your interest in improving CryptLock! This document explains how
to contribute code, bug reports, and documentation in a way that keeps the
project clean and safe for everyone.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Ethical Boundaries](#ethical-boundaries)
3. [Getting Started](#getting-started)
4. [Branching Strategy](#branching-strategy)
5. [Commit Message Format](#commit-message-format)
6. [Code Style](#code-style)
7. [Running Tests](#running-tests)
8. [Pull Request Checklist](#pull-request-checklist)
9. [Reporting Bugs](#reporting-bugs)
10. [Feature Requests](#feature-requests)

---

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).
Respectful, constructive communication only.

---

## Ethical Boundaries

CryptLock is a **defensive, educational** tool.  Contributions that do any of
the following will be **rejected without discussion**:

- Add real encryption of user files.
- Weaken or remove the safety gate that restricts process termination to
  approved simulation processes only (`APPROVED_SIMULATION_PROCESSES`).
- Add network communication, remote control, or exfiltration capability.
- Introduce actual malware behaviour, payloads, or obfuscation techniques.
- Remove or bypass false-positive reduction guards.

---

## Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/Ismail-shaik786/Ransomeware_detection_system.git
cd Ransomeware_detection_system
```

### 2. Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # linting + testing extras
```

> **Python 3.10+** is required (uses `match / case` structural pattern matching).

### 3. Verify Everything Works

```bash
python -m py_compile config.py detector/*.py utils/*.py process/*.py response/*.py
python main.py   # smoke-test the UI
```

---

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, release-ready code |
| `develop` | Integration branch — PRs merge here first |
| `feature/<short-name>` | New features |
| `fix/<issue-number>-<short-name>` | Bug fixes |
| `docs/<topic>` | Documentation-only changes |
| `refactor/<module>` | Internal refactoring (no behaviour change) |

**Always branch from `develop`, never from `main` directly.**

```bash
git checkout develop
git pull origin develop
git checkout -b feature/my-new-feature
```

---

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body — explain WHY, not what]

[optional footer — refs #issue]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code restructure, no behaviour change |
| `test` | Adding or fixing tests |
| `chore` | Tooling, dependencies, CI |
| `perf` | Performance improvement |

### Examples

```
feat(detector): add benign-burst monotone guard to risk engine

Suppresses HEAVY_MODIFICATIONS and BURST_ACTIVITY flags when >85% of
window events are a single type (e.g. all-MODIFIED from a file copy).
Real ransomware produces a mixed CREATE→MODIFY→RENAME→DELETE stream.

Closes #42
```

```
fix(entropy): skip inherently high-entropy file extensions

ZIP, JPEG, MP4 and similar formats always score HIGH entropy because
they are compressed/encoded by design. Scoring them causes false
positives on any ZIP compression or video render operation.
```

---

## Code Style

- **Formatter**: `black` (line length 88)
- **Linter**: `ruff`
- **Type hints**: Required on all public functions and class attributes
- **Docstrings**: NumPy / Google style (what the function does, its params,
  and return value)
- **Comments**: Explain *why*, not *what* — the code explains what

Run before every commit:

```bash
black .
ruff check .
```

---

## Running Tests

```bash
# Unit tests (fast, no filesystem side-effects)
pytest tests/ -v

# Quick false-positive regression (no external deps needed)
python tests/test_false_positives.py
```

All tests must pass before a PR is opened.

---

## Pull Request Checklist

Before opening a PR, confirm every item:

- [ ] Branched from `develop`, not `main`
- [ ] Commit messages follow Conventional Commits format
- [ ] `black .` applied — no formatting issues
- [ ] `ruff check .` passes — no lint errors
- [ ] All existing tests pass
- [ ] New behaviour is covered by at least one test
- [ ] Docstrings added/updated on changed functions
- [ ] `README.md` config table updated if you changed any `config.py` parameter
- [ ] No real malware behaviour introduced (see [Ethical Boundaries](#ethical-boundaries))
- [ ] PR description explains the *problem* being solved and the *approach* taken

---

## Reporting Bugs

Please open a **GitHub Issue** with:

1. **Summary** — one-line description of the problem
2. **Steps to reproduce** — exact commands / sequence of events
3. **Expected behaviour**
4. **Actual behaviour** — include terminal output / log excerpts
5. **Environment** — OS, Python version, `pip list` output

For **security vulnerabilities**, please read [SECURITY.md](SECURITY.md) and
follow the private disclosure process instead of opening a public issue.

---

## Feature Requests

Open a GitHub Issue with the `enhancement` label. Include:

- **Problem statement** — what user need does this address?
- **Proposed solution** — high-level design idea
- **Alternatives considered** — why this approach over others?
- **Ethical consideration** — confirm the feature stays within defensive use

---

_Thank you for keeping CryptLock safe and effective!_
