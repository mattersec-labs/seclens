# Dataset Coverage

SecLens tests against confirmed CVEs from real-world open source projects. The dataset is designed for balanced coverage across vulnerability categories and programming languages.

## Dataset Summary

| Metric | Count |
|--------|:-----:|
| Total tasks | 406 |
| True positive (vulnerable) | 203 |
| Post-patch (patched) | 203 |
| Vulnerability categories | 8 |
| Programming languages | 10 |
| Unique repositories | 93 |

## Vulnerability Categories

8 categories sourced from OWASP Top 10 (2021), OWASP API Security Top 10 (2023), and CWE Top 25 (2024). Only categories detectable by static analysis are included.

| Category | Tasks | Key CWEs | Description |
|----------|:-----:|----------|-------------|
| **Broken Access Control** | 41 | CWE-22 (Path Traversal), CWE-284/285 (Access Control), CWE-352 (CSRF), CWE-639 (IDOR), CWE-862/863 (Missing/Incorrect AuthZ) | Restrictions on authenticated users not properly enforced |
| **Cryptographic Failures** | 32 | CWE-295/296 (Cert Validation), CWE-326/327 (Weak Crypto), CWE-312 (Cleartext Storage), CWE-798 (Hardcoded Credentials) | Weak or misused cryptographic primitives exposing sensitive data |
| **Injection** | 31 | CWE-79 (XSS), CWE-89 (SQLi), CWE-77/78 (Command Injection), CWE-94 (Code Injection), CWE-611 (XXE), CWE-1336 (Template Injection) | Untrusted data sent to an interpreter as part of a command or query |
| **Improper Input Validation** | 29 | CWE-20 (Improper Validation), CWE-400 (Resource Consumption) | Missing or insufficient validation of external input |
| **SSRF** | 23 | CWE-918 (Server-Side Request Forgery) | Server fetches attacker-controlled URL without validation |
| **Authentication Failures** | 19 | CWE-287 (Improper Auth), CWE-306 (Missing Auth), CWE-384 (Session Fixation), CWE-522 (Insufficiently Protected Credentials) | Broken authentication mechanisms allowing identity compromise |
| **Deserialization / Integrity** | 18 | CWE-502 (Deserialization), CWE-915 (Mass Assignment), CWE-345 (Insufficient Authenticity), CWE-494 (Download Without Integrity) | Unsafe deserialization or missing integrity verification |
| **Memory Safety** | 10 | CWE-787 (OOB Write), CWE-125 (OOB Read), CWE-416 (Use After Free), CWE-476 (NULL Deref), CWE-190 (Integer Overflow) | Memory corruption from manual memory management |

## Programming Languages

10 languages covering web, systems, and enterprise development.

| Language | Tasks | Categories |
|----------|:-----:|:----------:|
| PHP | 27 | 7 |
| Go | 27 | 6 |
| Python | 24 | 5 |
| C# | 23 | 6 |
| Ruby | 18 | 5 |
| Java | 18 | 5 |
| C | 18 | 4 |
| Rust | 17 | 4 |
| JavaScript/TypeScript | 16 | 5 |
| C++ | 15 | 4 |

## Severity Distribution

Each task carries a severity rating from the CVE advisory. This enables severity-weighted scoring — missing a critical RCE costs more than missing a low-severity info leak.

| Severity | Tasks | Weight |
|----------|:-----:|:------:|
| Critical | 25 | 4x |
| High | 74 | 3x |
| Medium | 83 | 2x |
| Low | 21 | 1x |

## Task Types

Each CVE generates two tasks:

| Task Type | Ground Truth | Max Points | Count | Purpose |
|-----------|:------------:|:----------:|:-----:|---------|
| **true_positive** | Vulnerable | 3 | 203 | Can the model detect the vulnerability? |
| **post_patch** | Not vulnerable | 1 | 203 | Can the model correctly clear patched code? |

Post-patch tasks use the same function at the fix commit. This tests whether the model distinguishes between vulnerable and fixed code — the core false positive challenge.
