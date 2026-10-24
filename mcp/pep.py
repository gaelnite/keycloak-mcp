"""Policy enforcement point (PEP) for the Keycloak MCP server.

Stdlib only so the offline tests run without the MCP SDK. The PEP:
* maps a verified Keycloak token + tool spec to a Cedar request;
* calls the local Node PDP (cedar-wasm) over JSON lines with a hard 500 ms deadline;
* denies on any PDP/audit failure (no fallback to scope-only checks);
* appends a redacted audit record with the deciding policy IDs and bundle hash.

It never logs tool arguments, tokens, client secrets or approval tokens.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from tool_registry import ADMIN, READ, WRITE, ToolSpec

HERE = Path(__file__).resolve().parent
PDP_SCRIPT = HERE / "pdp.mjs"
DEFAULT_TIMEOUT_MS = 500
MAX_TIMEOUT_MS = 2000
ACTION = {READ: "Read", WRITE: "Write", ADMIN: "Admin"}


class PdpError(RuntimeError):
    """PDP unavailable, malformed response, or timeout. Callers must deny."""


class PepError(RuntimeError):
    """The PEP itself is misconfigured (missing node/PDP script)."""


@dataclass(frozen=True)
class Decision:
    decision: str
    reasons: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    bundle_hash: str = ""
    failed_closed: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _approval_facts(approval: Mapping[str, Any] | None) -> tuple[bool, str]:
    if not approval:
        return False, ""
    try:
        expires = float(approval.get("expiresIn", 0))
    except (TypeError, ValueError):
        expires = 0.0
    verified = bool(approval.get("verified")) and expires > 0
    return verified, str(approval.get("tool") or "")


def build_context(
    *,
    realm: str,
    extensions: Sequence[str],
    writes_enabled: bool,
    approval_verified: bool = False,
    approval_tool: str = "",
    tool_known: bool = True,
) -> dict[str, Any]:
    return {
        "resource": {"__entity": {"type": "KeycloakMCP::Resource", "id": f"realm:{realm}"}},
        "toolKnown": bool(tool_known),
        "writesEnabled": bool(writes_enabled),
        "extensions": sorted(set(extensions) | {"core"}),
        "approvalVerified": approval_verified,
        "approvalTool": approval_tool,
    }


class CedarPep:
    """Long-lived Node PDP + fail-closed authorization + redacted audit."""

    def __init__(
        self,
        *,
        pdp_script: str | os.PathLike[str] | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        audit_path: str | os.PathLike[str] | None = None,
        node: str | None = None,
    ) -> None:
        if not DEFAULT_TIMEOUT_MS <= int(timeout_ms) <= MAX_TIMEOUT_MS:
            raise PepError(f"timeout_ms must be {DEFAULT_TIMEOUT_MS}-{MAX_TIMEOUT_MS}")
        self.timeout = int(timeout_ms) / 1000.0
        self.audit_path = Path(audit_path) if audit_path else None
        self._script = Path(pdp_script) if pdp_script else PDP_SCRIPT
        self._node = node or shutil.which("node")
        if not self._node:
            raise PepError("node not found; the Cedar PDP requires Node 22+")
        if not self._script.is_file():
            raise PepError(f"Cedar PDP script not found: {self._script}")
        self._proc: subprocess.Popen[str] | None = None
        self._start()

    # -- lifecycle -------------------------------------------------------
    def _start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                [self._node, str(self._script)],
                cwd=str(self._script.parent),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise PepError(f"cannot start the Cedar PDP: {exc}") from exc
        # Startup loads and compiles the WASM bundle; give it more than one decision's
        # 500 ms budget. Per-decision deadlines stay at self.timeout.
        self.meta = self._request({"op": "ping"}, timeout=max(self.timeout, 2.0))

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def __enter__(self) -> "CedarPep":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- authorization ---------------------------------------------------
    def authorize(
        self,
        tool: ToolSpec,
        *,
        principal_type: str,
        principal_id: str,
        realm: str,
        extensions: Sequence[str],
        writes_enabled: bool = False,
        approval: Mapping[str, Any] | None = None,
        tool_known: bool = True,
    ) -> Decision:
        approval_verified, approval_tool = _approval_facts(approval)
        context = build_context(
            realm=realm,
            extensions=extensions,
            writes_enabled=writes_enabled,
            approval_verified=approval_verified,
            approval_tool=approval_tool,
            tool_known=tool_known,
        )
        try:
            response = self._request(
                {
                    "op": "authorize",
                    "principal": {
                        "type": f"KeycloakMCP::{principal_type}",
                        "id": principal_id,
                    },
                    "action": {"type": "KeycloakMCP::Action", "id": ACTION[tool.tier]},
                    "resource": {"type": "KeycloakMCP::Tool", "id": tool.name},
                    "context": context,
                }
            )
        except (PdpError, KeyError) as exc:
            decision = Decision(
                decision="deny",
                reasons=("pdp_unavailable",),
                errors=(str(exc),),
                failed_closed=True,
            )
        else:
            decision = Decision(
                decision=str(response["decision"]),
                reasons=tuple(response.get("determiningPolicies") or ()),
                errors=tuple(
                    str(item.get("message", "")) for item in response.get("errors") or []
                ),
                bundle_hash=str(response.get("bundleHash") or ""),
            )
        try:
            self._audit(tool, principal_type, principal_id, realm, decision)
        except OSError as exc:
            return Decision(
                decision="deny",
                reasons=("audit_unavailable",),
                errors=(str(exc),),
                failed_closed=True,
            )
        return decision

    # -- protocol --------------------------------------------------------
    def _request(
        self, payload: Mapping[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        proc = self._proc
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise PdpError("the Cedar PDP process is not running")
        try:
            proc.stdin.write(json.dumps(payload) + "\n")
            proc.stdin.flush()
        except OSError as exc:
            raise PdpError(f"cannot write to the Cedar PDP: {exc}") from exc
        try:
            deadline = self.timeout if timeout is None else timeout
            ready, _, _ = select.select([proc.stdout], [], [], deadline)
        except (OSError, ValueError) as exc:
            raise PdpError(f"cannot wait for the Cedar PDP: {exc}") from exc
        if not ready:
            self.close()
            raise PdpError(f"the Cedar PDP exceeded {deadline * 1000:.0f} ms")
        line = proc.stdout.readline()
        if not line:
            raise PdpError(f"the Cedar PDP exited: {self._stderr_tail()}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PdpError(f"the Cedar PDP returned malformed JSON: {exc}") from exc
        if not response.get("ok"):
            raise PdpError(
                f"Cedar PDP refused ({response.get('error')}): "
                f"{response.get('detail') or response.get('errors')}"
            )
        return response

    def _stderr_tail(self) -> str:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return ""
        try:
            return (proc.stderr.read() or "").strip()[-400:]
        except (OSError, ValueError):
            return ""

    # -- audit -----------------------------------------------------------
    def _audit(
        self,
        tool: ToolSpec,
        principal_type: str,
        principal_id: str,
        realm: str,
        decision: Decision,
    ) -> None:
        if self.audit_path is None:
            return
        record = {
            "ts": _now(),
            "tool": tool.name,
            "policyId": tool.policy_id,
            "tier": tool.tier,
            "extension": tool.extension,
            "principalType": principal_type,
            "principal": principal_id,
            "realm": realm,
            "decision": decision.decision,
            "reasons": list(decision.reasons),
            "failedClosed": decision.failed_closed,
            "bundleHash": decision.bundle_hash,
        }
        data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            str(self.audit_path), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)


def pep_from_env(env: Mapping[str, str] | None = None) -> CedarPep:
    values = dict(os.environ if env is None else env)
    try:
        timeout = int(values.get("KC_CEDAR_TIMEOUT_MS") or DEFAULT_TIMEOUT_MS)
    except ValueError as exc:
        raise PepError("KC_CEDAR_TIMEOUT_MS must be an integer") from exc
    return CedarPep(
        timeout_ms=timeout,
        audit_path=values.get("KC_MCP_AUDIT_LOG") or None,
    )
