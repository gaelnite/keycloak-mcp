"""Extension-aware tool registry for the Keycloak MCP reference server.

Pure stdlib so the policy tests can run without the MCP SDK or network. Every tool
declares the Keycloak scope it needs, the Cedar policy that authorizes it (the
``policy_id`` must exist in ``cedar/policies.cedar``) and the extension that owns it.
``extension == "core"`` is always available; any other value must appear in the
server's installed-extension set or the Cedar policy denies the call.
"""

from __future__ import annotations

from dataclasses import dataclass

READ = "read"
WRITE = "write"
ADMIN = "admin"
TIERS = (READ, WRITE, ADMIN)

# Extension names are the inventory keys used by the server and by Cedar entities.
EXTENSIONS = (
    "core",
    "metrics",
    "orgs",
    "magic-link",
    "home-idp",
    "restrict-client-auth",
    "config-cli",
    "kcwarden",
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    scopes: tuple[str, ...]
    policy_id: str
    tier: str
    extension: str = "core"
    write: bool = False

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"{self.name}: unknown tier {self.tier!r}")
        if self.extension not in EXTENSIONS:
            raise ValueError(f"{self.name}: unknown extension {self.extension!r}")
        if self.tier == WRITE and not self.write:
            raise ValueError(f"{self.name}: write-tier tools must set write=True")
        if not self.scopes:
            raise ValueError(f"{self.name}: at least one scope is required")
        if not self.policy_id.startswith("kc-"):
            raise ValueError(f"{self.name}: policy_id must start with kc-")


def _spec(name: str, description: str, scope: str, tier: str, extension: str = "core") -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        scopes=(scope,),
        policy_id=f"kc-{tier}-{name.replace('_', '-')}",
        tier=tier,
        extension=extension,
        write=(tier == WRITE),
    )


TOOLS: tuple[ToolSpec, ...] = (
    # -- realm / client / user / group / role reads -----------------------------
    _spec("list_realms", "List Keycloak realms visible to the caller.", "keycloak.realms.read", READ),
    _spec("get_realm", "Read one realm's settings.", "keycloak.realms.read", READ),
    _spec("list_clients", "List OIDC/SAML clients in a realm.", "keycloak.clients.read", READ),
    _spec("get_client", "Read one client's configuration.", "keycloak.clients.read", READ),
    _spec("list_users", "Search users in a realm.", "keycloak.users.read", READ),
    _spec("get_user", "Read one user's profile and role mappings.", "keycloak.users.read", READ),
    _spec("list_groups", "List groups in a realm.", "keycloak.groups.read", READ),
    _spec("list_roles", "List realm and client roles.", "keycloak.roles.read", READ),
    # -- events and observability ----------------------------------------------
    _spec("list_events", "Read recent user events from a realm.", "keycloak.events.read", READ),
    _spec(
        "list_admin_events",
        "Read recent admin events from a realm.",
        "keycloak.events.admin.read",
        READ,
    ),
    _spec(
        "metrics_health_summary",
        "Summarize Keycloak metrics and health endpoints.",
        "keycloak.metrics.read",
        READ,
        extension="metrics",
    ),
    # -- extension-aware reads --------------------------------------------------
    _spec(
        "get_extension_inventory",
        "List installed Keycloak extensions and the tools mapped to each.",
        "keycloak.extensions.read",
        READ,
    ),
    _spec(
        "list_organizations",
        "List organizations (Organizations extension).",
        "keycloak.orgs.read",
        READ,
        extension="orgs",
    ),
    _spec(
        "get_organization",
        "Read one organization (Organizations extension).",
        "keycloak.orgs.read",
        READ,
        extension="orgs",
    ),
    _spec(
        "get_home_idp_config",
        "Read home-IdP discovery configuration for a realm.",
        "keycloak.realms.read",
        READ,
        extension="home-idp",
    ),
    _spec(
        "inspect_restrict_client_auth_flow",
        "Inspect the restrict-client-auth authentication flow bindings.",
        "keycloak.clients.read",
        READ,
        extension="restrict-client-auth",
    ),
    # -- admin (read-only but privileged) --------------------------------------
    _spec(
        "config_cli_diff",
        "Diff desired config-cli state against the live realm (read-only).",
        "keycloak.config.read",
        ADMIN,
        extension="config-cli",
    ),
    _spec(
        "kcwarden_audit",
        "Run a read-only kcwarden audit and return findings.",
        "keycloak.audit.read",
        ADMIN,
        extension="kcwarden",
    ),
    # -- writes (registered only when KC_MCP_ENABLE_WRITES=1) -------------------
    _spec(
        "magic_link_create",
        "Create a magic-link action token for a user (extension).",
        "keycloak.users.manage",
        WRITE,
        extension="magic-link",
    ),
    _spec(
        "config_cli_apply",
        "Apply config-cli desired state to a realm (gated write).",
        "keycloak.config.apply",
        WRITE,
        extension="config-cli",
    ),
)

TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}
READ_TOOLS = tuple(tool for tool in TOOLS if tool.tier == READ)
WRITE_TOOLS = tuple(tool for tool in TOOLS if tool.write)
ADMIN_TOOLS = tuple(tool for tool in TOOLS if tool.tier == ADMIN)


def tools_for_extensions(installed: frozenset[str] | set[str]) -> tuple[ToolSpec, ...]:
    """Tools whose owning extension is installed (core always is)."""
    return tuple(
        tool
        for tool in TOOLS
        if tool.extension == "core" or tool.extension in installed
    )


def policy_ids() -> tuple[str, ...]:
    return tuple(tool.policy_id for tool in TOOLS)
