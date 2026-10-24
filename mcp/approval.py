"""Operation-bound human approval for Keycloak MCP writes.

An Ed25519 compact JWT with a short TTL; claims bind the approval to
`tool`, `action`, `target` (and `sub`, `jti`), verified offline against a public key.
The PEP receives only the derived facts (`approvalVerified`, `approvalTool`); the
token itself never reaches Cedar, audit records or logs.

For streamable-http the middleware stores the raw header in a contextvar; for stdio
the operator exports KC_MCP_APPROVAL for the one write they intend to make.
"""

from __future__ import annotations

import os
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Mapping

import jwt

APPROVAL_HEADER = "x-mcp-approval"
_APPROVAL_TOKEN: ContextVar[str | None] = ContextVar("kc_mcp_approval_token", default=None)


class ApprovalError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def set_approval_token(token: str | None) -> Any:
    return _APPROVAL_TOKEN.set(token)


def current_approval_token() -> str | None:
    return _APPROVAL_TOKEN.get()


def reset_approval_token(token: Any) -> None:
    _APPROVAL_TOKEN.reset(token)


@dataclass(frozen=True)
class ApprovalFacts:
    verified: bool
    tool: str
    expires_in: int

    def to_pep(self) -> dict[str, Any]:
        return {"verified": self.verified, "tool": self.tool, "expiresIn": self.expires_in}


class ApprovalVerifier:
    def __init__(
        self,
        public_key: Any,
        *,
        issuer: str,
        audience: str,
        max_ttl: int = 900,
        clock: Any = time.time,
    ) -> None:
        self.public_key = public_key
        self.issuer = issuer
        self.audience = audience
        self.max_ttl = int(max_ttl)
        self._clock = clock

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ApprovalVerifier | None":
        values = dict(os.environ if env is None else env)
        path = (values.get("KC_MCP_APPROVAL_PUBLIC_KEY_FILE") or "").strip()
        if not path:
            return None
        try:
            from cryptography.hazmat.primitives import serialization

            with open(path, "rb") as handle:
                public_key = serialization.load_pem_public_key(handle.read())
        except (OSError, ValueError) as exc:
            raise ApprovalError(f"cannot load KC_MCP_APPROVAL_PUBLIC_KEY_FILE: {exc}") from exc
        return cls(
            public_key,
            issuer=(values.get("KC_MCP_APPROVAL_ISSUER") or "keycloak-mcp-approval").strip(),
            audience=(values.get("KC_MCP_APPROVAL_AUDIENCE") or "keycloak-mcp").strip(),
            max_ttl=int(values.get("KC_MCP_APPROVAL_MAX_TTL") or "900"),
        )

    def verify(
        self,
        token: str,
        *,
        tool: str,
        action: str,
        target: str,
    ) -> ApprovalFacts:
        if not isinstance(token, str) or token.count(".") != 2:
            raise ApprovalError(
                "the X-MCP-Approval header is not a signed approval token; create one with "
                "the lab's approval CLI"
            )
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["exp", "iat", "sub", "jti", "tool", "action", "target"],
                    "verify_exp": True,
                    "verify_iat": False,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise ApprovalError("the approval token is invalid or expired") from exc
        now = self._clock()
        issued = float(claims["iat"])
        expires = float(claims["exp"])
        if issued > now + 60 or expires <= now or expires - issued > self.max_ttl:
            raise ApprovalError("the approval token is expired or its lifetime is too long")
        if claims.get("tool") != tool or claims.get("action") != action:
            raise ApprovalError(
                "the approval token is bound to a different tool or action; request a new approval"
            )
        if claims.get("target") not in (target, "*"):
            raise ApprovalError(
                "the approval token is bound to a different target; request a new approval"
            )
        return ApprovalFacts(verified=True, tool=str(claims["tool"]), expires_in=int(expires - now))
