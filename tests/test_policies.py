"""Offline policy/PEP tests for the Keycloak MCP reference.

The PEP tests replace the PDP transport with a fake, so they need no Node. A second
class exercises the real Cedar bundle when Node + cedar-wasm are present; if they are
missing those tests skip rather than fail.

Run from lab/keycloak-mcp:
    python3 -m unittest discover -s tests -t .
    .venv/bin/python -m unittest discover -s tests -t .
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

import gen_cedar  # noqa: E402
import pep as pep_module  # noqa: E402
import tool_registry  # noqa: E402
from pep import CedarPep, Decision, PdpError, PepError  # noqa: E402
from tool_registry import ADMIN, READ, TOOLS, TOOLS_BY_NAME, WRITE, ToolSpec  # noqa: E402

CEDAR = LAB / "cedar"
POLICIES = CEDAR / "policies.cedar"
ENTITIES = CEDAR / "entities.json"


def _tool(name: str) -> ToolSpec:
    return TOOLS_BY_NAME[name]


class RegistryTests(unittest.TestCase):
    def test_every_tool_declares_scope_policy_tier_extension(self) -> None:
        self.assertGreaterEqual(len(TOOLS), 20)
        names = [tool.name for tool in TOOLS]
        self.assertEqual(len(names), len(set(names)), "duplicate tool name")
        policy_ids = [tool.policy_id for tool in TOOLS]
        self.assertEqual(len(policy_ids), len(set(policy_ids)), "duplicate policy id")
        for tool in TOOLS:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.scopes)
                self.assertTrue(tool.policy_id.startswith("kc-"))
                self.assertIn(tool.tier, (READ, WRITE, ADMIN))
                self.assertIn(tool.extension, tool_registry.EXTENSIONS)
                self.assertEqual(tool.write, tool.tier == WRITE)

    def test_write_tools_are_the_extension_sensitive_ones(self) -> None:
        writes = {tool.name for tool in TOOLS if tool.write}
        self.assertEqual(writes, {"magic_link_create", "config_cli_apply"})
        for name in writes:
            self.assertEqual(_tool(name).tier, WRITE)

    def test_extension_filter_keeps_core_tools(self) -> None:
        visible = tool_registry.tools_for_extensions(frozenset({"orgs"}))
        names = {tool.name for tool in visible}
        self.assertIn("list_realms", names)
        self.assertIn("list_organizations", names)
        self.assertNotIn("config_cli_diff", names)

    def test_read_and_admin_partitions(self) -> None:
        self.assertTrue(all(tool.tier == READ for tool in tool_registry.READ_TOOLS))
        self.assertTrue(all(tool.tier == ADMIN for tool in tool_registry.ADMIN_TOOLS))
        self.assertTrue(all(tool.tier == WRITE for tool in tool_registry.WRITE_TOOLS))


class CedarBundleTests(unittest.TestCase):
    def test_checked_in_bundle_matches_the_registry(self) -> None:
        self.assertEqual(POLICIES.read_text(), gen_cedar.render_policies())
        self.assertEqual(ENTITIES.read_text(), gen_cedar.render_entities())

    def test_every_tool_policy_id_exists_exactly_once(self) -> None:
        text = POLICIES.read_text()
        for tool in TOOLS:
            with self.subTest(tool=tool.name):
                self.assertEqual(
                    text.count(f'@id("{tool.policy_id}")'),
                    1,
                    f"missing or duplicate policy for {tool.name}",
                )

    def test_deny_by_default_and_required_forbids(self) -> None:
        text = POLICIES.read_text()
        for policy_id in (
            "kc-deny-unknown-tool",
            "kc-deny-cross-realm",
            "kc-deny-extension-missing",
            "kc-deny-writes-disabled",
            "kc-deny-unapproved-write",
            "kc-deny-config-apply-without-admin",
        ):
            self.assertIn(f'@id("{policy_id}")', text)
        # Deny-by-default means there is no unconditional permit.
        self.assertNotIn("permit(principal, action, resource);", text)

    def test_write_policies_require_approval_and_enabled_writes(self) -> None:
        text = POLICIES.read_text()
        for tool in TOOLS:
            if not tool.write:
                continue
            start = text.index(f'@id("{tool.policy_id}")')
            end = text.index("};", start) + 2
            block = text[start:end]
            with self.subTest(tool=tool.name):
                self.assertIn("context.writesEnabled", block)
                self.assertIn("context.approvalVerified", block)
                self.assertIn("context.approvalTool == resource.name", block)
                self.assertIn("context.extensions.contains(resource.extension)", block)

    def test_policies_carry_no_secret_or_wildcard_permit(self) -> None:
        text = POLICIES.read_text()
        self.assertNotIn("password", text.lower())
        self.assertNotIn("secret", text.lower())
        self.assertNotIn("like ", text, "policies must not glob-match raw strings")

    def test_entities_cover_realms_principals_and_all_tools(self) -> None:
        entities = json.loads(ENTITIES.read_text())
        by_type: dict[str, list[dict]] = {}
        for entity in entities:
            by_type.setdefault(entity["uid"]["type"], []).append(entity)
        self.assertEqual(len(by_type["KeycloakMCP::Realm"]), 2)
        self.assertTrue(by_type["KeycloakMCP::User"])
        self.assertTrue(by_type["KeycloakMCP::Client"])
        tool_ids = {entity["uid"]["id"] for entity in by_type["KeycloakMCP::Tool"]}
        self.assertEqual(tool_ids, {tool.name for tool in TOOLS})
        cursor = next(e for e in by_type["KeycloakMCP::Client"] if e["uid"]["id"] == "mcp-cursor")
        self.assertEqual(cursor["attrs"]["scopes"], gen_cedar._READ_SCOPES)
        admin = next(e for e in by_type["KeycloakMCP::Client"] if e["uid"]["id"] == "mcp-admin")
        self.assertTrue(admin["attrs"]["admin"])

    def test_generated_entities_put_principals_in_their_realm(self) -> None:
        entities = json.loads(ENTITIES.read_text())
        alice = next(e for e in entities if e["uid"]["id"] == "alice")
        self.assertEqual(
            alice["parents"],
            [{"__entity": {"type": "KeycloakMCP::Realm", "id": "lab"}}],
        )


class FakePdp:
    """Replaces CedarPep._request; records requests and returns a canned decision."""

    def __init__(self, *, decision: str = "allow", bundle_hash: str = "a" * 64) -> None:
        self.decision = decision
        self.bundle_hash = bundle_hash
        self.requests: list[dict] = []
        self.error: Exception | None = None

    def _request(self, payload: dict) -> dict:
        self.requests.append(payload)
        if self.error is not None:
            raise self.error
        return {
            "ok": True,
            "decision": self.decision,
            "determiningPolicies": [payload["resource"]["id"] and "kc-test-policy"],
            "errors": [],
            "bundleHash": self.bundle_hash,
        }


def make_pep(fake: FakePdp, audit_path: str | os.PathLike[str] | None = None) -> CedarPep:
    instance = CedarPep.__new__(CedarPep)
    instance.timeout = 0.5
    instance.audit_path = Path(audit_path) if audit_path else None
    instance._request = fake._request  # type: ignore[method-assign]
    return instance


class PepDecisionTests(unittest.TestCase):
    def test_allow_carries_policy_and_bundle_hash(self) -> None:
        fake = FakePdp()
        decision = make_pep(fake).authorize(
            _tool("list_realms"),
            principal_type="Client",
            principal_id="mcp-claude",
            realm="lab",
            extensions=["orgs"],
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ("kc-test-policy",))
        self.assertEqual(len(decision.bundle_hash), 64)
        request = fake.requests[0]
        self.assertEqual(request["action"]["id"], "Read")
        self.assertEqual(request["resource"]["id"], "list_realms")
        self.assertEqual(request["principal"]["id"], "mcp-claude")

    def test_deny_is_returned_without_failing_closed(self) -> None:
        decision = make_pep(FakePdp(decision="deny")).authorize(
            _tool("list_realms"),
            principal_type="Client",
            principal_id="mcp-claude",
            realm="lab",
            extensions=[],
        )
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.failed_closed)

    def test_pdp_failure_fails_closed(self) -> None:
        fake = FakePdp()
        fake.error = PdpError("the Cedar PDP exceeded 500 ms")
        decision = make_pep(fake).authorize(
            _tool("list_realms"),
            principal_type="Client",
            principal_id="mcp-claude",
            realm="lab",
            extensions=[],
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.failed_closed)
        self.assertEqual(decision.reasons, ("pdp_unavailable",))

    def test_audit_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "not-a-directory"
            blocker.write_text("x")
            decision = make_pep(FakePdp(), audit_path=blocker / "audit.jsonl").authorize(
                _tool("list_realms"),
                principal_type="Client",
                principal_id="mcp-claude",
                realm="lab",
                extensions=[],
            )
        self.assertFalse(decision.allowed)
        self.assertIn("audit_unavailable", decision.reasons)

    def test_context_maps_approval_expiry_and_extensions(self) -> None:
        fake = FakePdp()
        pep = make_pep(fake)
        pep.authorize(
            _tool("magic_link_create"),
            principal_type="Client",
            principal_id="mcp-admin",
            realm="lab",
            extensions=["magic-link"],
            writes_enabled=True,
            approval={"verified": True, "tool": "magic_link_create", "expiresIn": 0},
        )
        context = fake.requests[0]["context"]
        self.assertFalse(context["approvalVerified"])
        self.assertTrue(context["writesEnabled"])
        self.assertIn("magic-link", context["extensions"])
        self.assertIn("core", context["extensions"])
        self.assertEqual(context["approvalTool"], "magic_link_create")

    def test_context_rejects_bad_approval_shape_without_crashing(self) -> None:
        fake = FakePdp()
        decision = make_pep(fake).authorize(
            _tool("magic_link_create"),
            principal_type="Client",
            principal_id="mcp-admin",
            realm="lab",
            extensions=["magic-link"],
            writes_enabled=True,
            approval={"verified": True, "tool": "other", "expiresIn": "soon"},
        )
        self.assertTrue(decision.allowed)  # fake PDP; approval mapping is what is tested
        self.assertFalse(fake.requests[0]["context"]["approvalVerified"])

    def test_audit_record_has_no_arguments_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "authz.jsonl"
            make_pep(FakePdp(), audit_path=audit).authorize(
                _tool("list_realms"),
                principal_type="Client",
                principal_id="mcp-claude",
                realm="lab",
                extensions=[],
            )
            text = audit.read_text()
            mode = stat.S_IMODE(os.stat(audit).st_mode)
        self.assertEqual(mode & 0o077, 0)
        record = json.loads(text.splitlines()[0])
        self.assertEqual(record["tool"], "list_realms")
        self.assertEqual(record["policyId"], "kc-read-list-realms")
        self.assertEqual(len(record["bundleHash"]), 64)
        self.assertNotIn("search", text)
        self.assertNotIn("realm=", text)

    def test_explicit_timeout_bounds_are_enforced(self) -> None:
        with self.assertRaises(PepError):
            CedarPep(timeout_ms=10)
        with self.assertRaises(PepError):
            CedarPep(timeout_ms=5000)

    def test_pep_from_env_rejects_non_integer_timeout(self) -> None:
        with self.assertRaises(PepError):
            pep_module.pep_from_env({"KC_CEDAR_TIMEOUT_MS": "soon"})


@unittest.skipUnless(shutil.which("node"), "Node is required for real Cedar checks")
class RealCedarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pep = CedarPep()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pep.close()

    def authorize(self, tool: str, **kwargs: object):
        parameters = dict(
            principal_type="Client",
            principal_id="mcp-claude",
            realm="lab",
            extensions=["orgs", "magic-link", "config-cli"],
        )
        parameters.update(kwargs)
        return self.pep.authorize(_tool(tool), **parameters)  # type: ignore[arg-type]

    def test_real_read_allowed_in_realm(self) -> None:
        decision = self.authorize("list_realms")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ("kc-read-list-realms",))

    def test_real_cross_realm_denied(self) -> None:
        decision = self.authorize("list_realms", realm="other")
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-cross-realm", decision.reasons)

    def test_real_extension_missing_denied(self) -> None:
        decision = self.authorize("list_organizations", extensions=[])
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-extension-missing", decision.reasons)

    def test_real_extension_installed_allowed(self) -> None:
        decision = self.authorize("list_organizations", extensions=["orgs"])
        self.assertTrue(decision.allowed)

    def test_real_write_requires_enabled_and_approval(self) -> None:
        approval = {"verified": True, "tool": "magic_link_create", "expiresIn": 60}
        disabled = self.authorize("magic_link_create", writes_enabled=False, approval=approval)
        self.assertIn("kc-deny-writes-disabled", disabled.reasons)
        no_approval = self.authorize("magic_link_create", writes_enabled=True, approval=None)
        self.assertFalse(no_approval.allowed)
        approved = self.authorize("magic_link_create", writes_enabled=True, approval=approval)
        self.assertTrue(approved.allowed)
        self.assertIn("kc-write-magic-link-create", approved.reasons)

    def test_real_admin_tier_requires_admin_principal(self) -> None:
        allowed = self.authorize("config_cli_diff", principal_id="mcp-admin")
        self.assertTrue(allowed.allowed)
        denied = self.authorize("config_cli_diff", principal_id="mcp-claude")
        self.assertFalse(denied.allowed)

    def test_real_unknown_tool_denied(self) -> None:
        unknown = ToolSpec(
            name="delete_everything",
            description="not registered",
            scopes=("keycloak.users.manage",),
            policy_id="kc-read-delete-everything",
            tier=READ,
        )
        decision = self.pep.authorize(
            unknown,
            principal_type="Client",
            principal_id="mcp-admin",
            realm="lab",
            extensions=[],
            tool_known=False,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-unknown-tool", decision.reasons)

    def test_real_disabled_config_cli_extension_denied(self) -> None:
        decision = self.authorize("config_cli_diff", principal_id="mcp-admin", extensions=[])
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-extension-missing", decision.reasons)


if __name__ == "__main__":
    unittest.main()
