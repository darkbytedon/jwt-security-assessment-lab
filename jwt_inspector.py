import base64
import binascii
import json
import math
import re
import sys
import time

from datetime import datetime, timezone


MAX_TOKEN_LENGTH = 65536

BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def reject_nonstandard_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def decode_segment(segment):
    """Strictly decode a Base64URL JWT header or payload."""

    if not isinstance(segment, str) or not segment:
        raise ValueError("JWT segment is empty.")

    if not BASE64URL_PATTERN.fullmatch(segment):
        raise ValueError("Segment contains invalid Base64URL characters.")

    if len(segment) % 4 == 1:
        raise ValueError("Invalid Base64URL segment length.")

    padded = segment + "=" * (-len(segment) % 4)

    try:
        decoded = base64.b64decode(
            padded,
            altchars=b"-_",
            validate=True
        )

        parsed = json.loads(
            decoded.decode("utf-8"),
            parse_constant=reject_nonstandard_constant
        )

    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError
    ) as error:
        raise ValueError(f"Segment decoding failed: {error}") from error

    if not isinstance(parsed, dict):
        raise ValueError("JWT header and payload must be JSON objects.")

    return parsed


def inspect_jwt(token):
    """Inspect JWT structure and claims without verifying its signature."""

    if not isinstance(token, str) or not token.strip():
        print("Error: No JWT was supplied.")
        return False

    token = token.strip()

    if len(token) > MAX_TOKEN_LENGTH:
        print("Error: Token exceeds the maximum inspection size.")
        return False

    parts = token.split(".")

    if len(parts) != 3:
        print("Error: Invalid JWT compact structure.")
        return False

    header_segment, payload_segment, signature_segment = parts

    if not signature_segment == "" and not BASE64URL_PATTERN.fullmatch(
        signature_segment
    ):
        print("Error: Invalid signature segment encoding.")
        return False

    try:
        header = decode_segment(header_segment)
        payload = decode_segment(payload_segment)

    except ValueError as error:
        print(f"Error: {error}")
        return False

    print("\n=== JWT HEADER ===")
    print(json.dumps(header, indent=4))

    print("\n=== JWT PAYLOAD ===")
    print(json.dumps(payload, indent=4))

    print("\n=== CLAIM INSPECTION ===")

    print("Subject:", payload.get("sub", "Not provided"))
    print("Issuer:", payload.get("iss", "Not provided"))
    print("Audience:", payload.get("aud", "Not provided"))
    print("Key ID:", header.get("kid", "Not provided"))
    print("Algorithm:", header.get("alg", "Not provided"))

    expiration = payload.get("exp")

    invalid_expiration = (
        isinstance(expiration, bool)
        or not isinstance(expiration, (int, float))
        or (
            isinstance(expiration, float)
            and not math.isfinite(expiration)
        )
    )

    if invalid_expiration:

        print("Expiration: Missing or invalid.")

    else:
        try:
            expiry = datetime.fromtimestamp(
                expiration,
                timezone.utc
            )

            print("Expiration:", expiry.isoformat())

            if expiration <= time.time():
                print("WARNING: Token expiration time has passed.")
            else:
                print("Status: Expiration time is in the future.")

        except (OverflowError, OSError, ValueError):
            print("Expiration: Timestamp is outside the supported range.")

    print("\n=== SECURITY NOTICE ===")
    print("JWT structure and claims were inspected.")
    print("The cryptographic signature was NOT verified.")
    print("Issuer, audience and other claims were NOT authenticated.")
    print("Decoded token contents must be treated as untrusted data.")

    return True


def main():
    try:
        token = input("Paste JWT for local inspection: ").strip()
    except EOFError:
        print("\nError: No input received.")
        return 1

    return 0 if inspect_jwt(token) else 1


if __name__ == "__main__":
    sys.exit(main())
