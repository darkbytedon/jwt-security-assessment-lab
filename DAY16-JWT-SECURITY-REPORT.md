# Day 16: JSON Web Token (JWT) Security Investigation

## 1. Introduction

This investigation explored JSON Web Tokens (JWTs), their structure, signing algorithms, security claims, and common authentication vulnerabilities.

The practical work involved:

- Understanding JWT structure.
- Decoding JWT headers and payloads using Python.
- Inspecting important token claims.
- Developing a reusable Python JWT inspection tool.
- Practising Linux file permissions.
- Studying common JWT authentication weaknesses.

## 2. JWT Structure

A signed JWT (JWS) commonly consists of three Base64URL-encoded components separated by dots:

1. Header
2. Payload
3. Signature

An encrypted JWT (JWE) commonly uses five components.

The header contains metadata such as the signing algorithm and key identifier.

The payload contains claims describing the token and its subject.

The signature provides integrity protection and allows the receiving application to verify the token.

**Important:** Decoding a JWT does not establish its authenticity.

## 3. JWT Header Investigation

The inspected token contained:

- Algorithm (`alg`): RS256
- Key identifier (`kid`): A UUID identifying the signing key.

RS256 uses RSA with SHA-256.

- The private key signs the token.
- The corresponding public key verifies the signature.

The `kid` value helps an application select the appropriate verification key from its trusted key set.

## 4. JWT Payload Investigation

The inspected token contained these claims:

| Claim | Meaning |
|---|---|
| `iss` | Token issuer |
| `exp` | Expiration timestamp |
| `sub` | Subject represented by the token |

The inspected subject was `wiener`, and the issuer was `portswigger`.

The expiration claim uses a Unix timestamp.

Other important JWT claims include:

- `aud`: Intended audience.
- `iat`: Time the token was issued.
- `nbf`: Time before which the token must not be accepted.

## 5. JWT Security Concepts

Important security considerations include:

- Enforcing token expiration.
- Validating relevant issuer and audience claims.
- Restricting accepted signing algorithms.
- Safely selecting trusted verification keys.
- Avoiding trust in user-controlled identity or role claims without proper validation.

Changing a signed token's payload without producing a valid replacement signature should cause signature verification to fail.

## 6. Python Integration

A Python tool named `jwt_inspector.py` was developed.

Its functions include:

- Splitting a JWT into three components.
- Decoding the header and payload.
- Displaying important claims.
- Converting the expiration timestamp into a readable date.
- Checking whether the expiration time has passed.
- Warning that decoding does not verify the signature.

The script uses Python's:

- `base64`
- `json`
- `time`
- `datetime`

**Limitation:** The tool does not perform cryptographic signature verification. Its output must not be treated as proof that a token is authentic.

## 7. Linux Security Practice

The Python script's permissions were inspected and modified.

Initial permissions:

`644`

Updated permissions:

`600`

Command used:

```bash
chmod 600 jwt_inspector.py
```

Verification command:

```bash
stat -c "%a %n" jwt_inspector.py
```

Result:

`600 jwt_inspector.py`

This restricts read and write access to the file owner.

Note that Linux permissions do not prevent the contents from being visible if the file is published in a public GitHub repository.

## 8. Knowledge Assessment

JWT knowledge assessment result: **5/5 (100%)**.

Topics tested:

- JWT structure.
- Signature verification.
- Expiration claims.
- Key identifiers.
- Authenticity versus decoding.

## 9. Practical Lab Status

Two practical labs were scheduled for further investigation:

1. JWT authentication bypass via unverified signature.
2. SSRF via OpenID dynamic client registration.

The JWT lab encountered a Burp Repeater HTTP/2 response-stream error, including when testing the original token. No successful authentication bypass was confirmed.

The SSRF lab was postponed because its required Collaborator workflow was not available in the user's Burp Community Edition setup.

Neither lab is recorded as completed.

## 10. Conclusion

This investigation developed foundational understanding of JWT structure, asymmetric signing, token claims, Python-based inspection, and Linux permissions.

The Python inspection tool provides a foundation for further security automation.

The next stage is to troubleshoot and complete the two postponed practical labs, then expand the Python tool with additional security checks and cryptographic verification.

## 11. Files Produced

- `jwt_inspector.py`
- `DAY16-JWT-SECURITY-REPORT.md`

## 12. Learning Outcomes

By the end of this investigation, the following skills were practised:

- Understanding signed JWT components.
- Identifying important JWT claims.
- Understanding RS256 and public-key verification.
- Recognising why decoding is not signature verification.
- Writing a basic Python security utility.
- Applying restrictive Linux file permissions.
- Documenting security investigations for a technical portfolio.

**Day 16 status:** Theory, Python inspection tool, Linux permissions, and knowledge assessment completed. Two practical labs remain pending.
