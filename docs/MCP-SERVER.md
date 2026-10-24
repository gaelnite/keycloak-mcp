# Keycloak MCP server (extension-aware)

**Status:** runnable in this workspace with a venv + Node 26; live Keycloak/SPIRE calls are unverified
(no access to a live deployment). Design rationale and the auth chain are in `AUTHZ.md`.

## Run

```bash
cd keycloak-mcp
python3.11 -m venv .venv
.venv/bin/pip install -r mcp/requirements.txt
cd mcp && npm install --no-audit --no-fund   # @cedar-policy/cedar-wasm 4.14.0
cd ..
export KC_URL=https://kc.lab.local:8443 KC_ISSUER=https://kc.lab.local:8443/realms/lab
export KC_AUDIENCE=https://mcp.lab.local/mcp KC_ALLOWED_CLIENT_IDS_FILE=$PWD/allowed-clients.txt  # contains the CIMD URL
export KC_EXTENSIONS=metrics,orgs,home-idp,restrict-client-auth,config-cli,kcwarden,magic-link
.venv/bin/python mcp/server.py --check                  # config + Cedar bundle + tool list
.venv/bin/python mcp/server.py --transport http --port 8766
KC_MCP_ACCESS_TOKEN_FILE=~/.config/keycloak-mcp/token .venv/bin/python mcp/server.py --transport stdio
```

`--check` starts the Cedar PDP, validates schema/policies/entities, prints the bundle hash and the
registered tools, then exits. HTTP binds loopback only; `/healthz` is unauthenticated, everything else
requires a Keycloak bearer token.

## Layout

| Path | Contents |
|---|---|
| `mcp/server.py` | FastMCP server, stdio/HTTP, token middleware, extension-aware tools, write/approval gate |
| `mcp/auth.py` | Keycloak access-token verifier, JWKS cache, exact `azp`/CIMD allowlist, scope parsing |
| `mcp/pep.py` | PEP: PDP lifecycle, 500 ms deadline, fail-closed decisions, redacted audit |
| `mcp/pdp.mjs` | Node PDP over JSON lines, real cedar-wasm 4.14.0, bootstrap validation |
| `mcp/tool_registry.py` | Single source of truth: tool, scope, policy_id, tier, extension |
| `mcp/gen_cedar.py` | Generates/checks `cedar/policies.cedar` + `cedar/entities.json` from the registry |
| `cedar/` | schema, generated policies/entities (26 policies, 20 tools) |
| `tests/test_policies.py` | Offline registry/bundle/PEP tests + real-Cedar tests when Node is present |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KC_URL` | required | Keycloak base URL (`https://kc.lab.example`); Admin API + metrics |
| `KC_ISSUER` | required | exact token issuer (`.../realms/lab`) |
| `KC_AUDIENCE` | required | MCP resource identifier (`https://mcp.lab.local/mcp`) |
| `KC_JWKS_URL` | issuer + `/protocol/openid-connect/certs` | HTTPS JWKS, no redirects, 1 MiB cap |
| `KC_ALLOWED_CLIENT_IDS` / `_FILE` | required | exact client ids/CIMD URLs; file = one per line |
| `KC_EXTENSIONS` | `core` | installed extension names; gates extension tools and Cedar facts |
| `KC_MCP_ENABLE_WRITES` | `0` | register write tools; requires an approval public key |
| `KC_MCP_ENABLE_ADMIN_TOOLS` | `0` | register `config_cli_diff`, `kcwarden_audit` |
| `KC_MCP_APPROVAL_PUBLIC_KEY_FILE` | unset | Ed25519 public key for `X-MCP-Approval` |
| `KC_MCP_AUDIT_LOG` | unset | JSONL decision log (0600, policy IDs + bundle hash, no args) |
| `KC_CEDAR_TIMEOUT_MS` | `500` | PDP deadline, 500–2000 ms; exceeded ⇒ deny |
| `KC_MCP_CLIENT_ENTITY_MAP` | `{}` | JSON map `azp → Cedar Client entity id`; default identity. Map the CIMD URL to `mcp-claude` or every call fails closed; `--check` lists unmapped clients. |
| `KC_METRICS_URL` / `KC_HEALTH_URL` | `{KC_URL}/metrics` / `/health` | observability summary |
| `KC_MAGIC_LINK_PATH` | unset | extension admin path template (`/admin/realms/{realm}/magic-link`) |
| `KC_CONFIG_CLI_CMD` / `KC_CONFIG_CLI_APPLY` | unset / `0` | config-cli argv (no shell); apply needs both flags |
| `KC_KCWARDEN_CMD` | unset | kcwarden argv (no shell) |
| `KC_MCP_ACCESS_TOKEN` / `_FILE` | unset | stdio-only short-lived Keycloak token; no anonymous stdio |
| `KC_MCP_ENABLE_WRITES` + `KC_MCP_ENABLE_ADMIN_TOOLS` | off | both are opt-in; read tools always register |

## Tools (20; policy id = `kc-<tier>-<tool>`)

| Tool | Scope | Tier | Extension |
|---|---|---|---|
| `list_realms`, `get_realm` | `keycloak.realms.read` | read | core |
| `list_clients`, `get_client` | `keycloak.clients.read` | read | core |
| `list_users`, `get_user` | `keycloak.users.read` | read | core |
| `list_groups` / `list_roles` | `keycloak.groups.read` / `.roles.read` | read | core |
| `list_events` / `list_admin_events` | `keycloak.events.read` / `.events.admin.read` | read | core |
| `get_extension_inventory` | `keycloak.extensions.read` | read | core |
| `metrics_health_summary` | `keycloak.metrics.read` | read | metrics |
| `list_organizations`, `get_organization` | `keycloak.orgs.read` | read | orgs |
| `get_home_idp_config` | `keycloak.realms.read` | read | home-idp |
| `inspect_restrict_client_auth_flow` | `keycloak.clients.read` | read | restrict-client-auth |
| `config_cli_diff` | `keycloak.config.read` | admin | config-cli |
| `kcwarden_audit` | `keycloak.audit.read` | admin | kcwarden |
| `magic_link_create` | `keycloak.users.manage` | write | magic-link |
| `config_cli_apply` | `keycloak.config.apply` | write | config-cli |

## Extension mapping (verify against your deployment)

| Extension | Tools | Endpoint assumption |
|---|---|---|
| core | realm/client/user/group/role/events/inventory | `/admin/realms/...` Keycloak Admin REST v26 |
| events | event reads (core endpoint) | p2-inc keycloak-events adds listeners/types; no separate tool |
| metrics | `metrics_health_summary` | `/metrics` + `/health`; metrics SPI is RISKY in `EXTENSIONS.md`, verify before enabling |
| orgs | organizations reads | `/admin/realms/{realm}/organizations` (Organizations feature enabled) |
| magic-link | `magic_link_create` | configured `KC_MAGIC_LINK_PATH`; extension endpoint shape must be confirmed |
| home-idp | `get_home_idp_config` | realm attributes containing `home`/`idp`; extension config key unverified |
| restrict-client-auth | flow inspection | `/authentication/flows`, alias contains `restrict` |
| config-cli | diff/apply | external `keycloak-config-cli` argv; diff appends `--dry-run`, apply needs approval + flag |
| kcwarden | audit | external `kcwarden` argv; output capped at 4 KB |

## MCP client configuration

Claude Code (project `.mcp.json`; same shape in `mcp/mcp.json`):

```json
{"mcpServers": {"keycloak-lab": {
  "command": "/path/to/lab/.venv/bin/python",
  "args": ["/path/to/lab/mcp/server.py", "--transport", "stdio"],
  "env": {"KC_URL": "https://kc.lab.local:8443", "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
          "KC_AUDIENCE": "https://mcp.lab.local/mcp", "KC_ALLOWED_CLIENT_IDS_FILE": "/path/to/allowed-clients.txt",
          "KC_EXTENSIONS": "metrics,orgs", "KC_MCP_ACCESS_TOKEN_FILE": "/path/to/token"}}}}
```

Cursor (`.cursor/mcp.json`) uses the same `mcpServers` object; for HTTP use
`{"url": "http://127.0.0.1:8766/mcp", "headers": {"Authorization": "Bearer <token>"}}`.

VS Code (`.vscode/mcp.json`) uses `servers` and a `type`:

```json
{"servers": {
  "keycloak-lab": {"type": "stdio", "command": "/path/to/lab/.venv/bin/python",
    "args": ["/path/to/lab/mcp/server.py", "--transport", "stdio"],
    "env": {"KC_URL": "https://kc.lab.local:8443", "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
            "KC_AUDIENCE": "https://mcp.lab.local/mcp", "KC_ALLOWED_CLIENT_IDS_FILE": "/path/to/allowed-clients.txt"}},
  "keycloak-lab-http": {"type": "http", "url": "http://127.0.0.1:8766/mcp",
    "headers": {"Authorization": "Bearer ${input:kcToken}"}}}}
```

## Tests

```bash
cd keycloak-mcp
python3 -m unittest discover -s tests -t .            # 28 pass, 13 skip (auth/server need venv)
.venv/bin/python -m unittest discover -s tests -t .   # 41 pass, incl. token + server-gate tests
.venv/bin/python mcp/server.py --check                # config + Cedar + tool inventory
```

The suite mocks the PDP transport for PEP failure/audit cases, and (when Node + `node_modules` exist)
runs the real Cedar bundle for allow, cross-realm, extension-missing, write-disabled, unapproved-write,
admin-tier and unknown-tool decisions.

## Not verified / out of scope

Not verified without a live deployment: Keycloak 26.8.1 CIMD feature/client policy, SVID/SPIFFE extension and
token-exchange endpoint, live JWKS, Admin API role mappings, Organizations/magic-link/home-idp endpoint
shapes, config-cli/kcwarden flags, and real MCP client handshakes. Out of scope: hosting CIMD documents,
SPIRE deployment, entity sync from Keycloak roles, consent UI, DCR, and secret/password fallbacks.
