import base64
import contextlib
import io
import json
import time
import unittest

import jwt_inspector


def encode_segment(value):
    raw = json.dumps(value).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(header=None, payload=None, signature="c2ln"):
    header = header or {"alg": "RS256", "kid": "test-key"}
    payload = payload or {"sub": "alice", "iss": "training.example"}

    return (
        f"{encode_segment(header)}."
        f"{encode_segment(payload)}."
        f"{signature}"
    )


class JWTInspectorTests(unittest.TestCase):

    def inspect(self, token):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = jwt_inspector.inspect_jwt(token)
        return result, output.getvalue()

    def test_valid_token_displays_claims(self):
        token = make_token()
        result, output = self.inspect(token)

        self.assertTrue(result)
        self.assertIn("alice", output)
        self.assertIn("RS256", output)
        self.assertIn("test-key", output)

    def test_signature_is_not_verified(self):
        result, output = self.inspect(make_token())

        self.assertTrue(result)
        self.assertIn("signature was NOT verified", output)

    def test_expired_token_warning(self):
        token = make_token(payload={"sub": "alice", "exp": 1})
        result, output = self.inspect(token)

        self.assertTrue(result)
        self.assertIn("Token expiration time has passed", output)

    def test_future_expiration(self):
        token = make_token(
            payload={"sub": "alice", "exp": time.time() + 3600}
        )
        result, output = self.inspect(token)

        self.assertTrue(result)
        self.assertIn("Expiration time is in the future", output)

    def test_missing_expiration(self):
        result, output = self.inspect(
            make_token(payload={"sub": "alice"})
        )

        self.assertTrue(result)
        self.assertIn("Missing or invalid", output)

    def test_boolean_expiration_rejected(self):
        result, output = self.inspect(
            make_token(payload={"exp": True})
        )

        self.assertTrue(result)
        self.assertIn("Missing or invalid", output)

    def test_malformed_token_structure(self):
        result, output = self.inspect("one.two")

        self.assertFalse(result)
        self.assertIn("Invalid JWT compact structure", output)

    def test_invalid_base64url_header(self):
        payload = encode_segment({"sub": "alice"})
        result, output = self.inspect(f"!!.{payload}.c2ln")

        self.assertFalse(result)
        self.assertIn("invalid Base64URL", output)

    def test_invalid_json_header(self):
        header = base64.urlsafe_b64encode(b"not-json").decode().rstrip("=")
        payload = encode_segment({"sub": "alice"})

        result, output = self.inspect(f"{header}.{payload}.c2ln")

        self.assertFalse(result)
        self.assertIn("Segment decoding failed", output)

    def test_payload_must_be_json_object(self):
        header = encode_segment({"alg": "RS256"})
        payload = encode_segment(["alice", "bob"])

        result, output = self.inspect(f"{header}.{payload}.c2ln")

        self.assertFalse(result)
        self.assertIn("must be JSON objects", output)

    def test_invalid_signature_encoding(self):
        token = make_token(signature="bad!")
        result, output = self.inspect(token)

        self.assertFalse(result)
        self.assertIn("Invalid signature segment encoding", output)

    def test_extreme_expiration_timestamp(self):
        token = make_token(payload={"exp": 1e30})
        result, output = self.inspect(token)

        self.assertTrue(result)
        self.assertIn("outside the supported range", output)

    def test_extremely_large_integer_expiration(self):
        token = make_token(
            payload={"exp": 10**1000}
        )
        result, output = self.inspect(token)

        self.assertTrue(result)
        self.assertIn("outside the supported range", output)

    def test_excessive_token_length(self):
        result, output = self.inspect("A" * 65537)

        self.assertFalse(result)
        self.assertIn("maximum inspection size", output)

    def test_empty_token(self):
        result, output = self.inspect("")

        self.assertFalse(result)
        self.assertIn("No JWT was supplied", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
