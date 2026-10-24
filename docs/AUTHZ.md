# Authorization: Keycloak (CIMD + SVID) → MCP → Cedar

**Status:** reference design for `this repository`, Keycloak 26.8.1. The POC evaluates real
Cedar 4.14.0 (`@cedar-policy/cedar-wasm`) and the Python PEP fails closed. Everything below marked
**unverified** needs a live reference deployment; this workspace has no Keycloak or SPIRE access.

## Verdict

Keycloak authenticates the caller and remains the source of scopes; Cedar authorizes each tool call and
is the only place tool-level policy lives. The PEP is deny-by-default and fails closed on any PDP or
audit error, so a Cedar outage cannot widen access. Keycloak and Cedar are not alternatives: Keycloak
answers "who is calling and what scopes does the token carry", Cedar answers "may this caller run this
tool in this realm, with this extension, right now".

## The chain

```text
Claude Code / Cursor / VS Code
  │  (1) workload identity: SPIRE agent issues a short-lived SVID
  ▼
Keycloak 26.8.1
  │  (2) client_id = https://cimd.lab.local:8444/client-metadata.json;
  │      client authentication = federated-jwt assertion backed by a SPIFFE
  │      JWT-SVID (identity provider `spiffe-lab`, trust domain lab.local)
  │  (3) access token: iss = https://kc.lab.local:8443/realms/lab,
  │      aud = https://mcp.lab.local/mcp, azp = the CIMD URL,
  │      scope = keycloak.realms.read ... exp ≤ 5 min
  ▼
MCP server (this project)
  │  (4) verify token → PEP facts → Cedar PDP decision → tool
  │      deny-by-default; PDP timeout 500 ms → deny; audit line with policy IDs
  ▼
Keycloak Admin REST API
  │  (5) the *caller's* access token is passed through; no service-account secret
  ▼
realm data / extension endpoints
```

### CIMD (Client ID Metadata Document)

Keycloak 26.8.1 ships CIMD as experimental (`--features=cimd`; client-policy executor
`client-id-metadata-document` plus a `client-id-uri` policy; upstream issue keycloak#45106). The flag
alone does nothing: the profile and policy must also match the URL's scheme/domain, or nothing is
fetched. A CIMD `client_id` is an HTTPS URL; Keycloak fetches the document and the token's `azp` is the
URL. Keycloak is stricter than the draft here: https, a path, no dot-segments/fragment/userinfo, and
query strings are rejected outright; documents are capped at 5 KB. This server never parses the URL as a
realm or path: it compares the full string against `KC_ALLOWED_CLIENT_IDS(_FILE)`, exactly, with no
port/case/trailing-slash normalisation. A changed URL is a different client by definition.

### SVID (SPIFFE Verifiable Identity Document)

The workload, not a human password, proves its identity: SPIRE issues a short-lived JWT-SVID to the MCP
client. Keycloak 26.8.1 has `client-auth-federated:v1` supported and the SPIFFE trust provider
`spiffe:v1` in Preview; the client uses authenticator `federated-jwt` with
`jwt.credential.issuer=spiffe-lab` and `jwt.credential.sub=spiffe://lab.local/workload/mcp-client`.
The SPIFFE identity provider validates the bundle endpoint and Keycloak issues the access token. This
removes long-lived client secrets and gives key rotation for free. **CIMD and SPIFFE are not joined in
26.8.1:** CIMD has no standard field for `federated-jwt`, so assume the SPIFFE client is pre-registered
with the CIMD URL as its `clientId`, and CIMD is the metadata/discovery test. The exact end-to-end join
is unverified; see `docs/AUTHN.md`. If SPIFFE is unavailable, use a confidential CIMD
client with `private_key_jwt`; never fall back to passwords or service accounts.

## Token validation (server side, deny by default)

| Check | Implementation |
|---|---|
| signature | RS256/RS384/ES256/ES384, `kid` required, JWKS cache 300 s, refresh on unknown kid |
| issuer | exact `KC_ISSUER` match (trailing slash normalised once) |
| audience | JWT `aud` must contain `KC_AUDIENCE` (`https://mcp.lab.local/mcp`) |
| lifetime | `exp`, `nbf`, `iat` with ≤60 s skew; token ≤16 KiB |
| client | `azp` (or `client_id`) must be in the exact allowlist; CIMD URLs pass unchanged |
| scopes | `scope`/`scp`; the server gate requires the tool scope, and Cedar also requires it from the synced principal |
| realm | derived from `KC_ISSUER` `/realms/lab` (or `KC_REALM`); must match the Cedar realm |
| failure | `401` JSON error with an instruction; never anonymous, never scope-only fallback |

## Cedar model

Namespace `KeycloakMCP`; entities `Realm`, `User`, `Client`, `Tool`, `Resource`; actions `Read`,
`Write`, `Admin`. Principals are members of their realm (`User in [Realm]`, `Client in [Realm]`), so
cross-realm denial is an entity-membership check, not a string compare.

Context is made of PEP facts, never raw URLs or search strings: `resource` (a `Resource` entity with a
realm), `toolKnown`, `writesEnabled`, `extensions` (installed set), `approvalVerified`, `approvalTool`.

| Decision | Rule |
|---|---|
| Read | tool tier `read`, caller scope contains `resource.requiredScope`, principal in target realm, extension installed |
| Admin | same, plus `principal.admin` and tier `admin`; no approval (read-only but privileged) |
| Write | tier `write`, `writesEnabled`, `approvalVerified`, `approvalTool == resource.name`, scope, realm, extension |
| Cross-realm | `forbid` when `!(principal in context.resource.realm)` |
| Unknown tool | `forbid` when `!context.toolKnown`; a tool without a Cedar entity never permits |
| Missing extension | `forbid` when the owning extension is not in `context.extensions` |
| Disabled writes | `forbid Write` when `!context.writesEnabled` |
| Unapproved write | `forbid Write` when approval is absent or bound to another tool |
| config-cli apply | additionally requires `principal.admin` |

One permit per tool, named by the registry `policy_id` (`kc-read-list-realms`, …), so an audit line names
the exact policy. The checked-in bundle is generated from `mcp/tool_registry.py`; `gen_cedar.py --check`
fails CI if the registry, policies and entities drift.

## Fail-closed, audit, bundle

- PEP starts the Node PDP once, validates schema/policies/entities at startup and keeps a SHA-256 bundle
  hash. Any startup failure refuses to serve.
- Per call: JSON line to `mcp/pdp.mjs`, `select` deadline **500 ms** (`KC_CEDAR_TIMEOUT_MS` 500–2000);
  timeout, crash, malformed response or Cedar error → `deny` with `pdp_unavailable`, never a fallback.
- Audit record: timestamp, tool, `policyId`, tier, extension, principal, realm, decision, deciding policy
  IDs, `failedClosed`, bundle hash. It contains no tokens, arguments, search text or approval tokens.
- The bundle is generated + hashed; production should sign the hash with a dedicated Ed25519 key and
  verify at startup (`docs/MCP-SERVER.md` (and the authn setup in `docs/AUTHN.md`)), like the approval key but a different key.

## HITL and writes

Writes are off unless `KC_MCP_ENABLE_WRITES=1`, which itself requires an approval public key. Each write
needs `X-MCP-Approval: <Ed25519 JWT>` with `tool`, `action`, `target`, short `exp`; the PEP passes only
`approvalVerified`/`approvalTool` to Cedar. Cedar also forbids writes without approval, so a PEP bug is
not sufficient to write. `config_cli_apply` adds `KC_CONFIG_CLI_APPLY=1` and `principal.admin`.

## Threat model delta

| # | Risk | Control |
|---|---|---|
| K1 | Stolen token replayed from another realm | realm from issuer + entity membership + short exp; no cross-realm Cedar permit |
| K2 | CIMD URL spoofing / query tricks | exact-string `azp` allowlist, HTTPS issuer/JWKS, no URL normalisation |
| K3 | SVID extension misconfiguration | fail closed if issuer/JWKS/audience do not match; document the exact extension in your deployment |
| K4 | PDP outage or slow loris | 500 ms deadline, deny, audit `pdp_unavailable`, health check |
| K5 | Extension tool exposed when extension absent | installed-extension set + Cedar forbid; startup inventory |
| K6 | CLI tool argument injection (`config-cli`, `kcwarden`) | argv list, no shell, fixed configured binary, timeout, admin tier + approval for apply |
| K7 | Token passthrough privileges | Keycloak Admin API called with caller token; the caller's realm-management roles are the ceiling |
| K8 | Audit leaks data | no args/tokens; 0600 file; only policy IDs and facts |

## Out of scope

CIMD document hosting and rotation, SPIRE deployment, Keycloak feature enablement, multi-tenant entity
sync from Keycloak roles, consent UI, DCR, password/service-account fallback, and live verification against
26.8.1. The next document (`MCP-SERVER.md`) covers running the server and the exact tool map.
