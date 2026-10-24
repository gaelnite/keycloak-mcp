"""Keycloak token-verification tests (need the server venv: PyJWT + cryptography).

These are skipped under a bare system Python that lacks PyJWT; the required offline
policy suite is tests/test_policies.py.
"""

from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - depends on the interpreter
    HAVE_CRYPTO = False

if HAVE_CRYPTO:
    from auth import KeycloakAuthConfig, KeycloakTokenVerifier, TokenError

ISSUER = "https://kc.lab.example/realms/lab"
CLIENT_URL = "https://clients.example/claude.json"


class _FakeJwks:
    def __init__(self, public_key):
        self.public_key = public_key

    async def get_key(self, kid: str):
        if kid != "k1":
            raise TokenError("unknown key id")
        return self.public_key


@unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography are required")
class TokenVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.config = KeycloakAuthConfig.from_env(
            {
                "KC_ISSUER": ISSUER,
                "KC_AUDIENCE": "keycloak-mcp",
                "KC_ALLOWED_CLIENT_IDS": f"{CLIENT_URL} mcp-cursor",
            }
        )
        cls.verifier = KeycloakTokenVerifier(cls.config, jwks=_FakeJwks(cls.public_key))

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": "keycloak-mcp",
            "sub": "user-1",
            "iat": now,
            "exp": now + 300,
            "azp": CLIENT_URL,
            "scope": "keycloak.realms.read keycloak.users.read",
            "realm_access": {"roles": ["mcp-admin"]},
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "k1"})

    def verify(self, token: str):
        return asyncio.run(self.verifier.verify(token))

    def test_valid_token_yields_claims_and_scopes(self) -> None:
        claims = self.verify(self.token())
        self.assertEqual(claims.subject, "user-1")
        self.assertEqual(claims.client_id, CLIENT_URL)
        self.assertEqual(claims.realm, "lab")
        self.assertTrue(claims.admin)
        self.assertIn("keycloak.realms.read", claims.scopes)
        self.assertTrue(claims.allows("keycloak.users.read"))

    def test_cimd_url_allowlist_is_exact(self) -> None:
        with self.assertRaises(TokenError) as caught:
            self.verify(self.token(azp=CLIENT_URL + "/"))
        self.assertIn("allowlisted", str(caught.exception))

    def test_client_id_claim_is_accepted_when_azp_is_absent(self) -> None:
        token = self.token()
        # Re-encode without azp but with client_id.
        decoder = jwt.decode(token, options={"verify_signature": False})
        decoder.pop("azp")
        decoder["client_id"] = "mcp-cursor"
        signed = jwt.encode(decoder, self.private_key, algorithm="RS256", headers={"kid": "k1"})
        self.assertEqual(self.verify(signed).client_id, "mcp-cursor")

    def test_wrong_audience_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(aud="some-other-api"))

    def test_expired_token_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(exp=int(time.time()) - 120))

    def test_wrong_issuer_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(iss="https://evil.example/realms/lab"))

    def test_unknown_algorithm_is_rejected(self) -> None:
        token = jwt.encode({"iss": ISSUER}, "x" * 40, algorithm="HS256", headers={"kid": "k1"})
        with self.assertRaises(TokenError):
            self.verify(token)

    def test_scp_list_is_parsed(self) -> None:
        token = self.token(scope=None, scp=["keycloak.realms.read", "keycloak.groups.read"])
        claims = self.verify(token)
        self.assertEqual(claims.scopes, frozenset({"keycloak.realms.read", "keycloak.groups.read"}))

    def test_config_requires_an_allowlist(self) -> None:
        with self.assertRaises(TokenError):
            KeycloakAuthConfig.from_env(
                {"KC_ISSUER": ISSUER, "KC_AUDIENCE": "keycloak-mcp"}
            )

    def test_allowlist_file_keeps_a_comma_inside_a_url(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.txt"
            path.write_text("https://clients.example/cb?state=1,2\n")
            config = KeycloakAuthConfig.from_env(
                {
                    "KC_ISSUER": ISSUER,
                    "KC_AUDIENCE": "keycloak-mcp",
                    "KC_ALLOWED_CLIENT_IDS_FILE": str(path),
                }
            )
        self.assertEqual(
            config.allowed_client_ids, frozenset({"https://clients.example/cb?state=1,2"})
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
