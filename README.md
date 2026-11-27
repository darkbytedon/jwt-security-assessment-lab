# JWT Security Assessment and Python Inspector

A practical cybersecurity project exploring JSON Web Token (JWT) structure, security claims, signing algorithms and common authentication weaknesses.

This repository includes a Python JWT inspection utility, automated tests and technical reports documenting the investigation.

## Project Overview

The project demonstrates how to inspect JWT headers and payloads using Python while understanding the security difference between decoding a token and verifying its cryptographic signature.

## Python JWT Inspector

The `jwt_inspector.py` tool provides:

- JWT compact-structure inspection.
- Base64URL header decoding.
- Payload claim decoding.
- Inspection of subject (`sub`), issuer (`iss`) and audience (`aud`).
- Inspection of algorithm (`alg`) and key identifier (`kid`).
- Expiration timestamp interpretation.
- Detection of malformed token input.
- Clear warnings about the absence of signature verification.

### Security Limitation

This is an inspection and decoding utility, not a JWT authentication or verification tool.

It does not:
- Verify cryptographic signatures.
- Validate trusted issuers.
- Validate intended audiences.
- Establish token authenticity.
- Perform cryptographic key verification.

Decoded claims must be treated as untrusted until validated by a properly configured authentication system.

## Technologies

- Python
- Base64URL encoding and decoding
- JSON
- Datetime and timestamp handling
- Python unittest
- Linux / Ubuntu

## Installation and Usage

No third-party Python packages are required for the inspector itself.

Clone the repository:

    git clone https://github.com/darkbytedon/jwt-security-assessment-lab.git
    cd jwt-security-assessment-lab

Run the inspector:

    python3 jwt_inspector.py

Paste a disposable JWT training token when prompted.

Use fictional or laboratory tokens. Do not paste live production tokens or confidential authentication credentials into this tool.

## Automated Testing

The project contains 15 automated tests covering:

1. Valid JWT inspection.
2. Header and claim display.
3. Signature-verification warning.
4. Expired tokens.
5. Future expiration timestamps.
6. Missing expiration claims.
7. Boolean expiration values.
8. Malformed token structure.
9. Invalid Base64URL input.
10. Invalid JSON headers.
11. Non-object payloads.
12. Invalid signature encoding.
13. Extreme expiration timestamps.
14. Extremely large integer timestamps.
15. Empty and oversized token input.

Run the tests:

    python3 -m unittest -v test_jwt_inspector.py

**Recorded local result: 15/15 tests passed.**

These tests verify the inspection utility's input handling and reporting behaviour. They do not demonstrate cryptographic signature verification.

## Repository Structure

    jwt-security-assessment-lab/
    ├── jwt_inspector.py
    ├── test_jwt_inspector.py
    ├── .gitignore
    ├── DAY16-JWT-SECURITY-REPORT.md
    └── DAY16-LINUX-SECURITY-REPORT.md

## JWT Security Investigation

The Day 16 investigation covered:

- JWT header, payload and signature structure.
- JWS and JWE concepts.
- RS256 and RSA signing concepts.
- Key identifiers (`kid`).
- Issuer, subject and expiration claims.
- Audience, issued-at and not-before claims.
- Authentication and signature-verification weaknesses.

Read the [Day 16 JWT Security Report](DAY16-JWT-SECURITY-REPORT.md).

## Linux Security Investigation

The related Linux investigation covered:

- Linux user and group permissions.
- File ownership.
- chmod and chown.
- Umask configuration.
- Sensitive authentication files.
- Sudo privileges.
- Restrictive file permissions.

Read the [Day 16 Linux Security Report](DAY16-LINUX-SECURITY-REPORT.md).

## Outstanding Practical Labs

The original Day 16 report records two practical labs as pending:

1. JWT authentication bypass through an unverified signature.
2. SSRF through OpenID dynamic client registration.

These exercises have not been recorded as successfully completed. They remain future learning objectives.

## Skills Demonstrated

- JWT structure and claim analysis.
- Python security-tool development.
- Input validation and error handling.
- Expiration timestamp interpretation.
- Automated testing.
- Linux file permissions.
- Security documentation.
- Understanding authentication and authorization limitations.

## Disclaimer

This project is an educational cybersecurity exercise. The inspection utility does not authenticate JWTs or establish their integrity.

The project is not a production security verification tool or a report of a client engagement.

---

**Author:** DarkByteDon
**Programme:** 60 Days of Cybersecurity Learning
**Project:** JWT Security Assessment and Python Inspection
