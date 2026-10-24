"""Server-side gate order tests (need the MCP SDK; skipped on bare Python)."""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import importlib.util

    # The lab directory itself is named mcp, so importing "mcp" can succeed as a
    # namespace package. Probe a real SDK submodule instead.
    HAVE_MCP = importlib.util.find_spec("mcp.server.fastmcp") is not None
except (ImportError, ValueError):  # pragma: no cover - depends on the interpreter
    HAVE_MCP = False

if HAVE_MCP:
    import server
    from auth import TokenClaims
    from pep import Decision


class _RecordingPep:
    def __init__(self) -> None:
        self.calls = 0

    def authorize(self, *args, **kwargs):
        self.calls += 1
        return Decision("deny", reasons=("test-deny",))


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server gate tests")
class ServerGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = server.ServerConfig.from_env(
            {
                "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
                "KC_AUDIENCE": "https://mcp.lab.local/mcp",
                "KC_URL": "https://kc.lab.local:8443",
                "KC_ALLOWED_CLIENT_IDS": "https://cimd.lab.local:8444/client-metadata.json",
                "KC_EXTENSIONS": "orgs,config-cli",
            }
        )

    def setUp(self) -> None:
        self._old_runtime = server._RUNTIME
        self.pep = _RecordingPep()
        server._RUNTIME = server.Runtime(config=self.config, pep=self.pep, admin=None)

    def tearDown(self) -> None:
        server._RUNTIME = self._old_runtime
        server._CLAIMS.set(None)

    def claims(self, *, scopes, admin=False) -> TokenClaims:
        return TokenClaims(
            subject="alice",
            client_id="https://cimd.lab.local:8444/client-metadata.json",
            scopes=frozenset(scopes),
            realm="lab",
            admin=admin,
            expires_at=9_999_999_999,
            issuer=self.config.auth.issuer,
            audience=self.config.auth.audience,
        )

    def test_missing_token_scope_is_denied_before_the_pep(self) -> None:
        server._CLAIMS.set(self.claims(scopes=[]))
        result = asyncio.run(server._authorized_call(server.SPECS["list_realms"]))
        self.assertIn("scope", result["error"].lower())
        self.assertEqual(self.pep.calls, 0)

    def test_admin_tier_needs_the_token_role(self) -> None:
        server._CLAIMS.set(self.claims(scopes=["keycloak.config.read"], admin=False))
        result = asyncio.run(server._authorized_call(server.SPECS["config_cli_diff"]))
        self.assertIn("mcp-admin", result["error"])
        self.assertEqual(self.pep.calls, 0)

    def test_scope_and_admin_pass_reach_the_pep(self) -> None:
        server._CLAIMS.set(self.claims(scopes=["keycloak.config.read"], admin=True))
        result = asyncio.run(server._authorized_call(server.SPECS["config_cli_diff"]))
        self.assertEqual(self.pep.calls, 1)
        self.assertIn("Cedar denied", result["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
