#!/usr/bin/env python3
"""Extension-aware Keycloak MCP server with Cedar authorization.

Run:
    python3 mcp/server.py --transport stdio
    python3 mcp/server.py --transport http --port 8766
    python3 mcp/server.py --check

Authentication: Keycloak access token (iss/aud/exp, JWKS cache, azp/CIMD allowlist,
scopes). Authorization: one PEP decision per tool call against a local Cedar PDP
(cedar-wasm). Writes are disabled unless KC_MCP_ENABLE_WRITES=1 and every write needs
an X-MCP-Approval token. No secrets or tool arguments are logged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shlex
import subprocess
import sys
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence

import httpx
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken as SdkAccessToken
from mcp.server.fastmcp import FastMCP
from starlette.authentication import AuthCredentials

from approval import (
    ApprovalError,
    ApprovalVerifier,
    current_approval_token,
    reset_approval_token,
    set_approval_token,
)
from auth import (
    KeycloakAuthConfig,
    KeycloakTokenVerifier,
    TokenClaims,
    TokenError,
    bearer_from_header,
)
from pep import CedarPep, PepError, pep_from_env
from tool_registry import ADMIN, TOOLS, ToolSpec

HERE = Path(__file__).resolve().parent
DEFAULT_PORT = 8766
MAX_TOOL_ROWS = 50
HTTP_TIMEOUT = 15.0

_CLAIMS: ContextVar[TokenClaims | None] = ContextVar("kc_mcp_claims", default=None)
_CALLER_TOKEN: ContextVar[str | None] = ContextVar("kc_mcp_caller_token", default=None)
_STDIO_CLAIMS: TokenClaims | None = None
_STDIO_TOKEN: str | None = None
_RUNTIME: "Runtime | None" = None

log = logging.getLogger("keycloak-mcp")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(Exception):
    pass


def _https_base(raw: str) -> str:
    from urllib.parse import urlparse

    value = (raw or "").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError("KC_URL must be an https:// base URL with a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("KC_URL must not contain credentials, a query or a fragment")
    return value


@dataclass(frozen=True)
class ServerConfig:
    auth: KeycloakAuthConfig
    base_url: str
    extensions: frozenset[str]
    writes_enabled: bool
    admin_tools_enabled: bool
    audit_log: str | None
    client_entity_map: Mapping[str, str]
    metrics_url: str
    health_url: str
    magic_link_path: str | None
    config_cli_cmd: tuple[str, ...]
    kcwarden_cmd: tuple[str, ...]
    config_cli_apply: bool
    approval: ApprovalVerifier | None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ServerConfig":
        values = dict(os.environ if env is None else env)
        auth = KeycloakAuthConfig.from_env(values)
        base_url = _https_base(values.get("KC_URL") or "")
        extensions = frozenset(
            part.strip()
            for part in (values.get("KC_EXTENSIONS") or "core").replace(",", " ").split()
            if part.strip()
        )
        try:
            entity_map = json.loads(values.get("KC_MCP_CLIENT_ENTITY_MAP") or "{}")
        except json.JSONDecodeError as exc:
            raise ConfigError(f"KC_MCP_CLIENT_ENTITY_MAP is not JSON: {exc}") from exc
        if not isinstance(entity_map, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in entity_map.items()
        ):
            raise ConfigError("KC_MCP_CLIENT_ENTITY_MAP must be a JSON object of string pairs")
        try:
            approval = ApprovalVerifier.from_env(values)
        except ApprovalError as exc:
            raise ConfigError(str(exc)) from exc
        writes_enabled = _truthy(values.get("KC_MCP_ENABLE_WRITES"))
        if writes_enabled and approval is None:
            raise ConfigError(
                "KC_MCP_ENABLE_WRITES=1 requires KC_MCP_APPROVAL_PUBLIC_KEY_FILE; writes "
                "cannot be enabled without independent human approval"
            )
        return cls(
            auth=auth,
            base_url=base_url,
            extensions=extensions,
            writes_enabled=writes_enabled,
            admin_tools_enabled=_truthy(values.get("KC_MCP_ENABLE_ADMIN_TOOLS")),
            audit_log=(values.get("KC_MCP_AUDIT_LOG") or "").strip() or None,
            client_entity_map=entity_map,
            metrics_url=(values.get("KC_METRICS_URL") or f"{base_url}/metrics").strip(),
            health_url=(values.get("KC_HEALTH_URL") or f"{base_url}/health").strip(),
            magic_link_path=(values.get("KC_MAGIC_LINK_PATH") or "").strip() or None,
            config_cli_cmd=tuple(shlex.split(values.get("KC_CONFIG_CLI_CMD") or "")),
            kcwarden_cmd=tuple(shlex.split(values.get("KC_KCWARDEN_CMD") or "")),
            config_cli_apply=_truthy(values.get("KC_CONFIG_CLI_APPLY")),
            approval=approval,
        )

    def redacted(self) -> dict[str, Any]:
        return {
            "issuer": self.auth.issuer,
            "audience": self.auth.audience,
            "realm": self.auth.realm,
            "jwks_url": self.auth.jwks_url,
            "allowed_client_ids": sorted(self.auth.allowed_client_ids),
            "base_url": self.base_url,
            "extensions": sorted(self.extensions),
            "writes_enabled": self.writes_enabled,
            "admin_tools_enabled": self.admin_tools_enabled,
            "approval_configured": self.approval is not None,
            "audit_log": self.audit_log,
            "config_cli_configured": bool(self.config_cli_cmd),
            "kcwarden_configured": bool(self.kcwarden_cmd),
        }


@dataclass
class Runtime:
    config: ServerConfig
    pep: CedarPep
    admin: "KeycloakAdmin"


# ---------------------------------------------------------------------------
# caller context
# ---------------------------------------------------------------------------
def current_claims() -> TokenClaims:
    claims = _CLAIMS.get() or _STDIO_CLAIMS
    if claims is None:
        raise TokenError("No authenticated caller in this request", code="invalid_token")
    return claims


def current_token() -> str:
    token = _CALLER_TOKEN.get() or _STDIO_TOKEN
    if not token:
        raise TokenError("No caller token available for the Admin API call", code="invalid_token")
    return token


def principal_for(claims: TokenClaims, config: ServerConfig) -> tuple[str, str] | None:
    """Map a Keycloak client to a Cedar Client entity.

    When an entity map is configured, an unmapped client fails closed instead of
    falling back to its raw id (which could match a stale entity in entities.json).
    With no map at all, keep the development fallback to the raw client id.
    """
    mapped = config.client_entity_map.get(claims.client_id)
    if mapped is not None:
        return "Client", mapped
    if not config.client_entity_map:
        return "Client", claims.client_id
    return None


def _runtime() -> Runtime:
    if _RUNTIME is None:
        raise ConfigError("server runtime is not initialised")
    return _RUNTIME


# ---------------------------------------------------------------------------
# Keycloak Admin API (caller-token passthrough; no service-account secret)
# ---------------------------------------------------------------------------
class KeycloakAdmin:
    def __init__(self, config: ServerConfig, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=HTTP_TIMEOUT,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        client = await self._http()
        response = await client.get(
            path,
            params=dict(params or {}),
            headers={"Authorization": f"Bearer {current_token()}", "Accept": "application/json"},
        )
        if response.status_code == 401:
            raise TokenError("Keycloak rejected the caller token for the Admin API", code="invalid_token")
        if response.status_code == 403:
            raise PermissionError(
                "Keycloak denied the Admin API call; the caller needs the matching realm-management role"
            )
        if response.status_code >= 400:
            raise RuntimeError(f"Keycloak Admin API returned HTTP {response.status_code}")
        return response.json()

    async def post(self, path: str, payload: Mapping[str, Any]) -> Any:
        client = await self._http()
        response = await client.post(
            path,
            json=dict(payload),
            headers={"Authorization": f"Bearer {current_token()}", "Accept": "application/json"},
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Keycloak Admin API returned HTTP {response.status_code}")
        return response.json() if response.content else {}

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()


def _capped(items: Any) -> Any:
    return items[:MAX_TOOL_ROWS] if isinstance(items, list) else items


# ---------------------------------------------------------------------------
# tool implementations
# ---------------------------------------------------------------------------
async def list_realms(admin: KeycloakAdmin, **_: Any) -> Any:
    return _capped(await admin.get("/admin/realms"))


async def get_realm(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    return await admin.get(f"/admin/realms/{realm}")


async def list_clients(admin: KeycloakAdmin, realm: str, search: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS, "first": 0}
    if search:
        params["search"] = search
    return _capped(await admin.get(f"/admin/realms/{realm}/clients", params=params))


async def get_client(admin: KeycloakAdmin, realm: str, client_id: str, **_: Any) -> Any:
    matches = await admin.get(
        f"/admin/realms/{realm}/clients", params={"clientId": client_id, "max": 1}
    )
    if not matches:
        raise RuntimeError(f"no client with clientId {client_id!r} in realm {realm!r}")
    return await admin.get(f"/admin/realms/{realm}/clients/{matches[0]['id']}")


async def list_users(admin: KeycloakAdmin, realm: str, search: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS, "first": 0, "briefRepresentation": "true"}
    if search:
        params["search"] = search
    return _capped(await admin.get(f"/admin/realms/{realm}/users", params=params))


async def get_user(admin: KeycloakAdmin, realm: str, user_id: str, **_: Any) -> Any:
    return await admin.get(f"/admin/realms/{realm}/users/{user_id}")


async def list_groups(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    return _capped(await admin.get(f"/admin/realms/{realm}/groups", params={"max": MAX_TOOL_ROWS}))


async def list_roles(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    return _capped(await admin.get(f"/admin/realms/{realm}/roles", params={"max": MAX_TOOL_ROWS}))


async def list_events(admin: KeycloakAdmin, realm: str, event_type: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS}
    if event_type:
        params["type"] = event_type
    return _capped(await admin.get(f"/admin/realms/{realm}/events", params=params))


async def list_admin_events(admin: KeycloakAdmin, realm: str, operation: str = "", **_: Any) -> Any:
    params: dict[str, Any] = {"max": MAX_TOOL_ROWS}
    if operation:
        params["operation"] = operation
    return _capped(await admin.get(f"/admin/realms/{realm}/admin-events", params=params))


async def metrics_health_summary(admin: KeycloakAdmin, config: ServerConfig, **_: Any) -> Any:
    client = await admin._http()
    summary: dict[str, Any] = {}
    try:
        metrics = await client.get(config.metrics_url)
        summary["metrics"] = {
            "status": metrics.status_code,
            "lines": len(metrics.text.splitlines()) if metrics.status_code == 200 else 0,
            "bytes": len(metrics.content),
        }
    except httpx.HTTPError as exc:
        summary["metrics"] = {"error": exc.__class__.__name__}
    try:
        health = await client.get(config.health_url)
        summary["health"] = {"status": health.status_code, "body": health.text[:200]}
    except httpx.HTTPError as exc:
        summary["health"] = {"error": exc.__class__.__name__}
    return summary


async def get_extension_inventory(config: ServerConfig, **_: Any) -> Any:
    return {
        "installed": sorted(config.extensions),
        "tools": {
            extension: [tool.name for tool in TOOLS if tool.extension == extension]
            for extension in sorted(config.extensions | {"core"})
        },
    }


async def list_organizations(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    return _capped(
        await admin.get(f"/admin/realms/{realm}/organizations", params={"max": MAX_TOOL_ROWS})
    )


async def get_organization(admin: KeycloakAdmin, realm: str, org_id: str, **_: Any) -> Any:
    return await admin.get(f"/admin/realms/{realm}/organizations/{org_id}")


async def get_home_idp_config(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    document = await admin.get(f"/admin/realms/{realm}")
    attributes = document.get("attributes") if isinstance(document, dict) else {}
    attributes = attributes if isinstance(attributes, dict) else {}
    return {
        "realm": realm,
        "homeIdpKeys": {
            key: value
            for key, value in attributes.items()
            if "home" in key.lower() or "idp" in key.lower()
        },
    }


async def inspect_restrict_client_auth_flow(admin: KeycloakAdmin, realm: str, **_: Any) -> Any:
    flows = await admin.get(f"/admin/realms/{realm}/authentication/flows")
    matches = [
        {
            "alias": flow.get("alias"),
            "providerId": flow.get("providerId"),
            "builtIn": flow.get("builtIn"),
            "topLevel": flow.get("topLevel"),
        }
        for flow in flows or []
        if isinstance(flow, dict) and "restrict" in str(flow.get("alias") or "").lower()
    ]
    return {"matches": matches, "count": len(matches)}


def _run(argv: Sequence[str], *, timeout: float = 30.0) -> dict[str, Any]:
    if not argv:
        raise ConfigError("this tool needs a configured command (see docs/MCP-SERVER.md)")
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False, shell=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"command failed to run: {exc.__class__.__name__}") from exc
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-1000:],
    }


async def config_cli_diff(config: ServerConfig, **_: Any) -> Any:
    return _run(config.config_cli_cmd + ("--dry-run",), timeout=60.0)


async def config_cli_apply(config: ServerConfig, **_: Any) -> Any:
    if not config.config_cli_apply:
        raise ConfigError("KC_CONFIG_CLI_APPLY=1 is required before config_cli_apply can run")
    return _run(config.config_cli_cmd, timeout=120.0)


async def kcwarden_audit(config: ServerConfig, **_: Any) -> Any:
    return _run(config.kcwarden_cmd, timeout=120.0)


async def magic_link_create(
    admin: KeycloakAdmin,
    config: ServerConfig,
    realm: str,
    user_id: str,
    ttl_seconds: int = 300,
    **_: Any,
) -> Any:
    if not config.magic_link_path:
        raise ConfigError(
            "KC_MAGIC_LINK_PATH is not configured; set it to the extension's admin path, "
            "for example /admin/realms/{realm}/magic-link"
        )
    return await admin.post(
        config.magic_link_path.format(realm=realm),
        {"userId": user_id, "ttlSeconds": int(ttl_seconds)},
    )


TOOL_IMPLS: dict[str, Callable[..., Awaitable[Any]]] = {
    "list_realms": list_realms,
    "get_realm": get_realm,
    "list_clients": list_clients,
    "get_client": get_client,
    "list_users": list_users,
    "get_user": get_user,
    "list_groups": list_groups,
    "list_roles": list_roles,
    "list_events": list_events,
    "list_admin_events": list_admin_events,
    "metrics_health_summary": metrics_health_summary,
    "get_extension_inventory": get_extension_inventory,
    "list_organizations": list_organizations,
    "get_organization": get_organization,
    "get_home_idp_config": get_home_idp_config,
    "inspect_restrict_client_auth_flow": inspect_restrict_client_auth_flow,
    "config_cli_diff": config_cli_diff,
    "kcwarden_audit": kcwarden_audit,
    "magic_link_create": magic_link_create,
    "config_cli_apply": config_cli_apply,
}


# ---------------------------------------------------------------------------
# authorization gate (scope gate is implicit: Cedar requires the scope)
# ---------------------------------------------------------------------------
def _error(message: str, *, policy_id: str, decision: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": message, "policy_id": policy_id}
    if decision is not None:
        payload["decision"] = decision.decision
        payload["reasons"] = list(decision.reasons)
        if decision.failed_closed:
            payload["failed_closed"] = True
    return payload


async def _authorized_call(spec: ToolSpec, **kwargs: Any) -> Any:
    runtime = _runtime()
    claims = current_claims()
    # Live scope gate: the token must carry every scope the tool declares. Cedar's
    # principal scopes are the synced authorization view, not a substitute for this.
    missing = [scope for scope in spec.scopes if scope not in claims.scopes]
    if missing:
        return _error(
            "the access token lacks the required scope(s): " + ", ".join(missing),
            policy_id=spec.policy_id,
        )
    if spec.tier == ADMIN and not claims.admin:
        return _error(
            "admin-tier tools require the mcp-admin realm role in the access token",
            policy_id=spec.policy_id,
        )
    mapped = principal_for(claims, runtime.config)
    if mapped is None:
        return _error(
            "this client is not mapped to a Cedar entity; add it to KC_MCP_CLIENT_ENTITY_MAP",
            policy_id=spec.policy_id,
        )
    principal_type, principal_id = mapped
    realm = str(kwargs.get("realm") or claims.realm)
    approval = None
    if spec.write:
        verifier = runtime.config.approval
        if verifier is None:
            return _error("writes are disabled or no approval key is configured", policy_id=spec.policy_id)
        token = current_approval_token() or os.environ.get("KC_MCP_APPROVAL")
        if not token:
            return _error(
                "this write requires an X-MCP-Approval token bound to the tool and target",
                policy_id=spec.policy_id,
            )
        try:
            facts = verifier.verify(
                token,
                tool=spec.name,
                action=spec.tier,
                target=kwargs.get("user_id") or kwargs.get("realm") or "*",
            )
        except ApprovalError as exc:
            return _error(str(exc), policy_id=spec.policy_id)
        approval = facts.to_pep()
    decision = runtime.pep.authorize(
        spec,
        principal_type=principal_type,
        principal_id=principal_id,
        realm=realm,
        extensions=runtime.config.extensions,
        writes_enabled=runtime.config.writes_enabled,
        approval=approval,
    )
    if not decision.allowed:
        return _error(
            "Cedar denied this tool call; see policy_id/reasons and the audit log",
            policy_id=spec.policy_id,
            decision=decision,
        )
    impl = TOOL_IMPLS[spec.name]
    try:
        return await impl(admin=runtime.admin, config=runtime.config, **kwargs)
    except PermissionError as exc:
        return {"error": str(exc), "policy_id": spec.policy_id}
    except (TokenError, RuntimeError, ConfigError) as exc:
        return {"error": str(exc), "policy_id": spec.policy_id}
    except httpx.HTTPError as exc:
        return {"error": f"Keycloak request failed: {exc.__class__.__name__}", "policy_id": spec.policy_id}


# -- explicit MCP tool signatures (FastMCP builds each input schema from these) --
async def tool_list_realms() -> Any:
    return await _authorized_call(SPECS["list_realms"])


async def tool_get_realm(realm: str) -> Any:
    return await _authorized_call(SPECS["get_realm"], realm=realm)


async def tool_list_clients(realm: str, search: str = "") -> Any:
    return await _authorized_call(SPECS["list_clients"], realm=realm, search=search)


async def tool_get_client(realm: str, client_id: str) -> Any:
    return await _authorized_call(SPECS["get_client"], realm=realm, client_id=client_id)


async def tool_list_users(realm: str, search: str = "") -> Any:
    return await _authorized_call(SPECS["list_users"], realm=realm, search=search)


async def tool_get_user(realm: str, user_id: str) -> Any:
    return await _authorized_call(SPECS["get_user"], realm=realm, user_id=user_id)


async def tool_list_groups(realm: str) -> Any:
    return await _authorized_call(SPECS["list_groups"], realm=realm)


async def tool_list_roles(realm: str) -> Any:
    return await _authorized_call(SPECS["list_roles"], realm=realm)


async def tool_list_events(realm: str, event_type: str = "") -> Any:
    return await _authorized_call(SPECS["list_events"], realm=realm, event_type=event_type)


async def tool_list_admin_events(realm: str, operation: str = "") -> Any:
    return await _authorized_call(SPECS["list_admin_events"], realm=realm, operation=operation)


async def tool_metrics_health_summary() -> Any:
    return await _authorized_call(SPECS["metrics_health_summary"])


async def tool_get_extension_inventory() -> Any:
    return await _authorized_call(SPECS["get_extension_inventory"])


async def tool_list_organizations(realm: str) -> Any:
    return await _authorized_call(SPECS["list_organizations"], realm=realm)


async def tool_get_organization(realm: str, org_id: str) -> Any:
    return await _authorized_call(SPECS["get_organization"], realm=realm, org_id=org_id)


async def tool_get_home_idp_config(realm: str) -> Any:
    return await _authorized_call(SPECS["get_home_idp_config"], realm=realm)


async def tool_inspect_restrict_client_auth_flow(realm: str) -> Any:
    return await _authorized_call(SPECS["inspect_restrict_client_auth_flow"], realm=realm)


async def tool_config_cli_diff() -> Any:
    return await _authorized_call(SPECS["config_cli_diff"])


async def tool_kcwarden_audit() -> Any:
    return await _authorized_call(SPECS["kcwarden_audit"])


async def tool_magic_link_create(realm: str, user_id: str, ttl_seconds: int = 300) -> Any:
    return await _authorized_call(
        SPECS["magic_link_create"], realm=realm, user_id=user_id, ttl_seconds=ttl_seconds
    )


async def tool_config_cli_apply() -> Any:
    return await _authorized_call(SPECS["config_cli_apply"])


SPECS = {tool.name: tool for tool in TOOLS}
TOOL_FUNCTIONS: dict[str, Callable[..., Awaitable[Any]]] = {
    "list_realms": tool_list_realms,
    "get_realm": tool_get_realm,
    "list_clients": tool_list_clients,
    "get_client": tool_get_client,
    "list_users": tool_list_users,
    "get_user": tool_get_user,
    "list_groups": tool_list_groups,
    "list_roles": tool_list_roles,
    "list_events": tool_list_events,
    "list_admin_events": tool_list_admin_events,
    "metrics_health_summary": tool_metrics_health_summary,
    "get_extension_inventory": tool_get_extension_inventory,
    "list_organizations": tool_list_organizations,
    "get_organization": tool_get_organization,
    "get_home_idp_config": tool_get_home_idp_config,
    "inspect_restrict_client_auth_flow": tool_inspect_restrict_client_auth_flow,
    "config_cli_diff": tool_config_cli_diff,
    "kcwarden_audit": tool_kcwarden_audit,
    "magic_link_create": tool_magic_link_create,
    "config_cli_apply": tool_config_cli_apply,
}


def _register_tools(mcp: FastMCP, config: ServerConfig) -> list[str]:
    registered: list[str] = []
    for spec in TOOLS:
        if spec.write and not config.writes_enabled:
            continue
        if spec.tier == ADMIN and not config.admin_tools_enabled:
            continue
        if spec.extension != "core" and spec.extension not in config.extensions:
            continue
        mcp.tool(name=spec.name, description=spec.description)(TOOL_FUNCTIONS[spec.name])
        registered.append(spec.name)
    return registered


# ---------------------------------------------------------------------------
# HTTP authentication middleware
# ---------------------------------------------------------------------------
class KeycloakAuthMiddleware:
    def __init__(self, app: Any, verifier: KeycloakTokenVerifier) -> None:
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        header = None
        approval = None
        for name, value in scope.get("headers") or ():
            if name.lower() == b"authorization":
                header = value.decode("latin-1")
            elif name.lower() == b"x-mcp-approval":
                approval = value.decode("latin-1")
        try:
            token = bearer_from_header(header)
            claims = await self.verifier.verify(token)
        except TokenError as exc:
            await self._reject(send, exc)
            return
        scope.setdefault("state", {})["keycloak_claims"] = claims
        scope["auth"] = AuthCredentials(scopes=sorted(claims.scopes))
        scope["user"] = AuthenticatedUser(
            SdkAccessToken(
                token="",
                client_id=claims.client_id,
                scopes=sorted(claims.scopes),
                expires_at=int(claims.expires_at),
                resource=claims.audience,
                subject=claims.subject,
                claims={"iss": claims.issuer, "realm": claims.realm},
            )
        )
        claims_token = _CLAIMS.set(claims)
        caller_token = _CALLER_TOKEN.set(token)
        approval_token = set_approval_token(approval)
        try:
            await self.app(scope, receive, send)
        finally:
            _CLAIMS.reset(claims_token)
            _CALLER_TOKEN.reset(caller_token)
            reset_approval_token(approval_token)

    @staticmethod
    async def _reject(send: Any, exc: TokenError) -> None:
        body = json.dumps({"error": exc.code, "error_description": str(exc)}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": exc.status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", f'Bearer error="{exc.code}"'.encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _stdio_token() -> str:
    direct = (os.environ.get("KC_MCP_ACCESS_TOKEN") or "").strip()
    if direct:
        return direct
    path = (os.environ.get("KC_MCP_ACCESS_TOKEN_FILE") or "").strip()
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            raise ConfigError(f"KC_MCP_ACCESS_TOKEN_FILE cannot be read: {exc}") from exc
    raise ConfigError(
        "stdio mode needs KC_MCP_ACCESS_TOKEN or KC_MCP_ACCESS_TOKEN_FILE with a short-lived "
        "Keycloak access token; there is no anonymous stdio fallback"
    )


def build_runtime(config: ServerConfig) -> Runtime:
    return Runtime(config=config, pep=pep_from_env(), admin=KeycloakAdmin(config))


def main(argv: Sequence[str] | None = None) -> int:
    global _RUNTIME, _STDIO_CLAIMS, _STDIO_TOKEN
    parser = argparse.ArgumentParser(prog="keycloak-mcp")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--check", action="store_true", help="validate config/Cedar bundle and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        config = ServerConfig.from_env()
        verifier = KeycloakTokenVerifier(config.auth)
        runtime = build_runtime(config)
        _RUNTIME = runtime
        mcp = FastMCP("keycloak-mcp")
        registered = _register_tools(mcp, config)
    except (ConfigError, TokenError, PepError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(
            json.dumps(
                {
                    "config": config.redacted(),
                    "cedar": {
                        "bundleHash": runtime.pep.meta.get("bundleHash"),
                        "cedarVersion": runtime.pep.meta.get("cedarVersion"),
                        "policies": len(runtime.pep.meta.get("policyIds") or []),
                    },
                    "tools": registered,
                    "unmapped_clients": sorted(
                        client_id
                        for client_id in config.auth.allowed_client_ids
                        if client_id not in config.client_entity_map
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        runtime.pep.close()
        asyncio.run(runtime.admin.aclose())
        asyncio.run(verifier.aclose())
        return 0
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("refusing to bind a non-loopback host", file=sys.stderr)
        runtime.pep.close()
        return 2
    if args.transport == "stdio":
        try:
            token = _stdio_token()
            claims = asyncio.run(verifier.verify(token))
        except (ConfigError, TokenError) as exc:
            print(f"authentication error: {exc}", file=sys.stderr)
            runtime.pep.close()
            return 2
        _STDIO_CLAIMS, _STDIO_TOKEN = claims, token
        print(
            f"keycloak-mcp: stdio, client={claims.client_id}, realm={claims.realm}, "
            f"tools={len(registered)}",
            file=sys.stderr,
        )
        try:
            mcp.run(transport="stdio")
        finally:
            runtime.pep.close()
            asyncio.run(runtime.admin.aclose())
            asyncio.run(verifier.aclose())
        return 0

    import uvicorn
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    app = mcp.streamable_http_app()

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "keycloak-mcp"})

    app.router.routes.insert(0, Route("/healthz", healthz, methods=["GET"]))
    app = KeycloakAuthMiddleware(app, verifier)
    config_uvicorn = uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")
    print(
        f"keycloak-mcp: http 127.0.0.1:{args.port}, realm={config.auth.realm}, "
        f"tools={len(registered)}",
        file=sys.stderr,
    )
    try:
        uvicorn.Server(config_uvicorn).run()
    finally:
        runtime.pep.close()
        asyncio.run(runtime.admin.aclose())
        asyncio.run(verifier.aclose())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
