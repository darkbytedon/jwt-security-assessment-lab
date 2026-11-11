import base64
import json
import time
from datetime import datetime, timezone


def decode_segment(segment):
    """Decode a Base64URL JWT segment."""
    segment += "=" * (-len(segment) % 4)
    decoded = base64.urlsafe_b64decode(segment)
    return json.loads(decoded)


def inspect_jwt(token):
    parts = token.split(".")

    if len(parts) != 3:
        print("Error: Invalid JWT structure.")
        return

    try:
        header = decode_segment(parts[0])
        payload = decode_segment(parts[1])
    except Exception as error:
        print(f"Decoding failed: {error}")
        return

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

    exp = payload.get("exp")

    if isinstance(exp, (int, float)):
        expiry = datetime.fromtimestamp(exp, timezone.utc)
        print("Expiration:", expiry.isoformat())

        if exp <= time.time():
            print("WARNING: Token has expired.")
        else:
            print("Status: Token has not yet expired.")
    else:
        print("Expiration: Missing or invalid.")

    print("\nIMPORTANT:")
    print("Decoding does NOT verify the JWT signature.")
    print("This script does not establish whether the token is authentic.")


token = input("Paste JWT: ").strip()
inspect_jwt(token)
