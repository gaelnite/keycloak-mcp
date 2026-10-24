"""Keycloak OIDC access-token verification for the MCP server.

Offline construction; network only on the first verification (JWKS). The verifier is
deliberately narrow: HTTPS JWKS, no redirects, bounded response, RS256/ES256 only,
exact issuer/audience, exp/iat enforced, `azp`/`client_id` exact allowlist (a CIMD
URL is accepted unchanged), and scopes parsed from `scope` or `scp`. Any failure is
an instruction-shaped :class:`TokenError`; there is no anonymous fallback.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlparse

import httpx
import jwt

ALLOWED_ALGORITHMS = frozenset({"RS256", "RS384", "ES256", "ES384"})
MAX_TOKEN_BYTES = 16_384
MAX_JWKS_BYTES = 1_048_576
DEFAULT_TIMEOUT = 5.0


class TokenError(Exception):
    def __init__(self, message: str, *, status: int = 401, code: str = "invalid_token") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _https_url(raw: str, field: str) -> str:
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TokenError(f"{field} must be an https:// URL with a host", code="server_error")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TokenError(
            f"{field} must not contain credentials, a query or a fragment",
            code="server_error",
        )
    return raw.rstrip("/")


def _split_list(raw: str | None) -> list[str]:
    """Whitespace-separated; a whitespace token starting https:// is never comma-split."""
    if not raw:
        return []
    values: list[str] = []
    for token in raw.split():
        if token.startswith("https://"):
            values.append(token)
        else:
            values.extend(part for part in token.split(",") if part)
    return values


@dataclass(frozen=True)
class KeycloakAuthConfig:
    issuer: str
    audience: str
    jwks_url: str
    allowed_client_ids: frozenset[str]
    realm: str
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    clock_skew: int = 60
    jwks_ttl: float = 300.0
    jwks_min_refresh: float = 30.0
    admin_role: str = "mcp-admin"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "KeycloakAuthConfig":
        values = dict(os.environ if env is None else env)
        issuer = _https_url((values.get("KC_ISSUER") or "").strip(), "KC_ISSUER")
        audience = (values.get("KC_AUDIENCE") or "").strip()
        if not audience:
            raise TokenError("KC_AUDIENCE is required (the MCP resource audience)", code="server_error")
        jwks_url = _https_url(
            (values.get("KC_JWKS_URL") or f"{issuer}/protocol/openid-connect/certs").strip(),
            "KC_JWKS_URL",
        )
        allowed: list[str] = []
        file_path = (values.get("KC_ALLOWED_CLIENT_IDS_FILE") or "").strip()
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as handle:
                    allowed.extend(
                        line.strip()
                        for line in handle
                        if line.strip() and not line.lstrip().startswith("#")
                    )
            except OSError as exc:
                raise TokenError(
                    f"KC_ALLOWED_CLIENT_IDS_FILE cannot be read: {exc}",
                    code="server_error",
                ) from exc
        allowed.extend(_split_list(values.get("KC_ALLOWED_CLIENT_IDS")))
        if not allowed:
            raise TokenError(
                "KC_ALLOWED_CLIENT_IDS or KC_ALLOWED_CLIENT_IDS_FILE is required; "
                "refusing to accept any client (deny by default)",
                code="server_error",
            )
        realm = (values.get("KC_REALM") or "").strip()
        if not realm:
            marker = "/realms/"
            realm = issuer.split(marker, 1)[1].split("/", 1)[0] if marker in issuer else ""
        if not realm:
            raise TokenError(
                "cannot derive the realm from KC_ISSUER; set KC_REALM", code="server_error"
            )
        algorithms = tuple(
            algorithm.upper()
            for algorithm in _split_list(values.get("KC_ALGORITHMS") or "RS256 ES256")
        )
        if not algorithms or any(algorithm not in ALLOWED_ALGORITHMS for algorithm in algorithms):
            raise TokenError(
                "KC_ALGORITHMS must be a subset of RS256 RS384 ES256 ES384",
                code="server_error",
            )
        try:
            skew = int(values.get("KC_CLOCK_SKEW") or "60")
            ttl = float(values.get("KC_JWKS_TTL") or "300")
            min_refresh = float(values.get("KC_JWKS_MIN_REFRESH") or "30")
        except ValueError as exc:
            raise TokenError("KC_CLOCK_SKEW/KC_JWKS_TTL must be numeric", code="server_error") from exc
        if not 0 <= skew <= 300 or not 30 <= ttl <= 3600 or not 1 <= min_refresh <= 300:
            raise TokenError("KC_CLOCK_SKEW/KC_JWKS_TTL/KC_JWKS_MIN_REFRESH out of range", code="server_error")
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            allowed_client_ids=frozenset(allowed),
            realm=realm,
            algorithms=algorithms,
            clock_skew=skew,
            jwks_ttl=ttl,
            jwks_min_refresh=min_refresh,
            admin_role=(values.get("KC_ADMIN_ROLE") or "mcp-admin").strip(),
        )


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    client_id: str
    scopes: frozenset[str]
    realm: str
    admin: bool
    expires_at: float
    issuer: str
    audience: str

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


class JwksCache:
    """One HTTPS JWKS URL, cached, bounded, no redirects, refresh on unknown kid."""

    def __init__(
        self,
        url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        ttl: float = 300.0,
        min_refresh: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        max_bytes: int = MAX_JWKS_BYTES,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise TokenError("JWKS URL must be https:// with a host", code="server_error")
        self.url = url
        self.host = parsed.hostname.lower()
        self._transport = transport
        self._timeout = timeout
        self._ttl = ttl
        self._min_refresh = min_refresh
        self._clock = clock
        self._max_bytes = max_bytes
        self._lock = asyncio.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
                headers={"Accept": "application/json", "User-Agent": "keycloak-mcp/0.1"},
            )
        return self._client

    async def refresh(self) -> None:
        client = await self._http()
        try:
            response = await client.get(self.url)
        except httpx.HTTPError as exc:
            raise TokenError(
                "Could not reach the Keycloak JWKS endpoint; retry, then check KC_JWKS_URL",
                status=503,
                code="temporarily_unavailable",
            ) from exc
        if response.status_code != 200:
            raise TokenError(
                f"The Keycloak JWKS endpoint returned HTTP {response.status_code}",
                status=503,
                code="temporarily_unavailable",
            )
        body = response.content or b""
        if len(body) > self._max_bytes:
            raise TokenError("The JWKS response was unexpectedly large", status=503)
        try:
            document = response.json()
        except ValueError as exc:
            raise TokenError("The JWKS endpoint did not return JSON", status=503) from exc
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise TokenError("The JWKS document is not {'keys': [...]}", status=503)
        try:
            key_set = jwt.PyJWKSet.from_dict(document)
        except Exception as exc:  # noqa: BLE001 - malformed key material
            raise TokenError("The JWKS document could not be parsed", status=503) from exc
        keys = {jwk.key_id: jwk for jwk in key_set.keys if jwk.key_id}
        if not keys:
            raise TokenError("The JWKS document contained no key IDs", status=503)
        self._keys = keys
        self._fetched_at = self._clock()

    async def get_key(self, kid: str) -> Any:
        async with self._lock:
            now = self._clock()
            fresh = bool(self._keys) and (now - self._fetched_at) < self._ttl
            if fresh and kid in self._keys:
                return self._keys[kid]
            if not fresh or (kid not in self._keys and now - self._fetched_at >= self._min_refresh):
                await self.refresh()
            key = self._keys.get(kid)
            if key is None:
                raise TokenError("The access token was signed with an unknown key id")
            return key

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _scope_claims(claims: Mapping[str, Any]) -> frozenset[str]:
    raw = claims.get("scope")
    if isinstance(raw, str):
        return frozenset(raw.split())
    scp = claims.get("scp")
    if isinstance(scp, list):
        return frozenset(str(item) for item in scp if isinstance(item, str))
    return frozenset()


def _client_id(claims: Mapping[str, Any]) -> str:
    for name in ("azp", "client_id"):
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    raise TokenError("The access token has no azp/client_id claim")


class KeycloakTokenVerifier:
    def __init__(self, config: KeycloakAuthConfig, *, jwks: Any | None = None) -> None:
        self.config = config
        self._jwks = jwks or JwksCache(
            config.jwks_url,
            ttl=config.jwks_ttl,
            min_refresh=config.jwks_min_refresh,
        )

    async def verify(self, token: str) -> TokenClaims:
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenError("The bearer token is not a signed JWT")
        if len(token) > MAX_TOKEN_BYTES:
            raise TokenError("The bearer token is too large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("The bearer token has a malformed JWT header") from exc
        algorithm = str(header.get("alg") or "").upper()
        if algorithm not in self.config.algorithms:
            raise TokenError("The token signing algorithm is not accepted")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("The access token has no kid header")
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get("iss")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.config.issuer:
            raise TokenError("The access token was not issued by the configured Keycloak issuer")
        key = await self._jwks.get_key(kid)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": False,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenError("The access token failed signature/claim validation") from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise TokenError("The access token has no subject")
        client_id = _client_id(claims)
        if client_id not in self.config.allowed_client_ids:
            raise TokenError(
                "The access token was issued to a client that is not allowlisted; add its "
                "client id or CIMD URL to KC_ALLOWED_CLIENT_IDS(_FILE)",
                code="invalid_client",
            )
        realm = self.config.realm
        roles = claims.get("realm_access", {}).get("roles") if isinstance(claims.get("realm_access"), dict) else []
        scopes = _scope_claims(claims)
        return TokenClaims(
            subject=subject,
            client_id=client_id,
            scopes=scopes,
            realm=realm,
            admin=isinstance(roles, list) and self.config.admin_role in roles,
            expires_at=float(claims["exp"]),
            issuer=self.config.issuer,
            audience=self.config.audience,
        )

    async def aclose(self) -> None:
        close = getattr(self._jwks, "aclose", None)
        if close is not None:
            await close()


def bearer_from_header(header: str | None) -> str:
    if not header or not header.strip():
        raise TokenError("Missing Authorization header; send 'Authorization: Bearer <token>'")
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise TokenError("Use the Bearer scheme with a Keycloak access token")
    return token.strip()
