# keycloak-mcp

This project builds on two Internet-Drafts and on Keycloak features that are still experimental or
preview:

- **Client ID Metadata Documents (CIMD)**: [`draft-ietf-oauth-client-id-metadata-document-02`](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
  (Keycloak feature `cimd`, experimental, off by default)
- **OAuth SPIFFE Client Authentication**: [`draft-ietf-oauth-spiffe-client-auth-02`](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/)
  (Keycloak feature `spiffe`, preview, off by default)
- **Cedar**: stable engine, but the policy model here is a reference design, not a product.

APIs, config keys and defaults may change without notice while the drafts evolve.

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Keycloak that replaces the usual
admin-REST wrapper with an identity-first design: MCP clients authenticate with a **SPIFFE JWT-SVID bound to a
Client ID Metadata Document**, receive a short-lived Keycloak token, and every tool call is authorized by
**Cedar** before it reaches the Keycloak Admin API.

## What it does

- **20 tools** (16 read, 2 write, 2 admin) across realms, clients, users, groups, roles, events, metrics and
  Keycloak extensions. Writes and admin tools are **not registered** unless explicitly enabled.
- **Keycloak token verification** (issuer, audience, lifetime, JWKS cache, exact client allowlist) with no
  anonymous fallback and no client secret.
- **Cedar PEP/PDP** with deny-by-default, 26 policies, a 500 ms decision deadline, fail-closed behaviour and a
  redacted audit log.
- **Extension-aware tools**, the MCP knows which Keycloak extensions are installed and exposes only their tools.

## Authentication and authorization

```text
MCP client                         Keycloak 26.8.1                      MCP server
  │  client_id = CIMD URL             │                                    │
  │  JWT-SVID (client_assertion) ────►│ CIMD executor fetches the document │
  │                                   │ SPIFFE IdP verifies the SVID       │
  │◄──────────── access token ────────│ (aud, azp = CIMD URL, scopes)      │
  │                                                                        │
  └────────────────── Bearer token ──────────────────────────────────────►│
                                                                           │ verify JWT → scope gate
                                                                           │ → Cedar PEP → tool
                                                                           │ → Keycloak Admin API
```

- The **client identity** is an HTTPS URL (CIMD). The **proof** is a SPIFFE JWT-SVID, not a shared secret.
- The **Cedar** decision sees the authenticated principal, the tool, the realm and PEP-derived facts
  (canonicalised path/command, approval, extension availability).
- **Writes** additionally require an Ed25519 approval token bound to tool + action + target.
- **Token passthrough:** the MCP calls the Admin API with the caller's token; the caller's Keycloak roles are the
  privilege ceiling.

## Extensions covered

| Extension | Upstream | MCP tools | In the image? |
|---|---|---|---|
| Core Keycloak | [keycloak.org](https://www.keycloak.org/) | `list_realms`, `get_realm`, `list_clients`, `get_client`, `list_users`, `get_user`, `list_groups`, `list_roles`, `list_events`, `list_admin_events`, `get_extension_inventory` | built in |
| Metrics (native, 26.x) | [Keycloak metrics](https://www.keycloak.org/server/configuration-production) | `metrics_health_summary` | built in |
| Organizations | [native](https://www.keycloak.org/docs/latest/server_admin/) | `list_organizations`, `get_organization` | native; p2-inc variant not shipped |
| Magic Link | [p2-inc/keycloak-magic-link](https://github.com/p2-inc/keycloak-magic-link) | `magic_link_create` (write, opt-in) | yes |
| Home IdP Discovery | [sventorben/keycloak-home-idp-discovery](https://github.com/sventorben/keycloak-home-idp-discovery) | `get_home_idp_config` | no (26.8 artifact pending) |
| Restrict Client Auth | [sventorben/keycloak-restrict-client-auth](https://github.com/sventorben/keycloak-restrict-client-auth) | `inspect_restrict_client_auth_flow` | no (26.8 artifact pending) |
| keycloak-config-cli | [adorsys/keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli) | `config_cli_diff`, `config_cli_apply` (admin/write) | external binary |
| kcwarden | [iteratec/kcwarden](https://github.com/iteratec/kcwarden) | `kcwarden_audit` | external CLI |
| MFA bundle | [netzbegruenung/keycloak-mfa-plugins](https://github.com/netzbegruenung/keycloak-mfa-plugins) | none directly (auth-flow configuration) | yes |

Compatibility details, exact artifact URLs and the "popular ≠ 26.8-ready" finding are in
[docs/EXTENSIONS.md](docs/EXTENSIONS.md).

## Quick start

Prerequisites: Podman 4.5+ (rootless), Python 3.11+, Node 22+, Terraform 1.6+, Ansible 2.15+. Keycloak 26.8.1 is
built by the playbook.

```bash
git clone https://github.com/gaelnite/keycloak-mcp.git ~/Dev/keycloak-mcp
cd ~/Dev/keycloak-mcp
make up      # build image, start stack, apply Terraform, mint SVID, verify
make down    # stop and remove containers, volumes and generated configuration
```

The playbook is idempotent and passes **12/12** end-to-end checks. See [docs/AUTOMATION.md](docs/AUTOMATION.md) for
the lifecycle and alternate ports, [docs/TERRAFORM.md](docs/TERRAFORM.md) for realm provisioning, and
[docs/AUTHN-RESULTS.md](docs/AUTHN-RESULTS.md) for the verified authentication results.

## Documentation

| Document | Contents |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Podman, certificates, quadlets, optimized build, upgrade |
| [docs/TERRAFORM.md](docs/TERRAFORM.md) | Realm provisioning, what Terraform manages, the client-policy gap |
| [docs/AUTOMATION.md](docs/AUTOMATION.md) | One-command spin-up and teardown, variables and ports |
| [docs/AUTHN.md](docs/AUTHN.md) | Keycloak 26.8 CIMD + SPIFFE configuration from source |
| [docs/AUTHN-RESULTS.md](docs/AUTHN-RESULTS.md) | What was verified live, plus corrections to the config guide |
| [docs/AUTHZ.md](docs/AUTHZ.md) | Cedar schema, policies, PEP/PDP contract |
| [docs/MCP-SERVER.md](docs/MCP-SERVER.md) | Token verification, tools, client configuration |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Day-2 runbook: health, backup, upgrade, troubleshooting |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, review findings, production hardening delta |
| [docs/EXTENSIONS.md](docs/EXTENSIONS.md) | Extension compatibility matrix and artifact pins |

## Compatibility and status

- Verified against Keycloak **26.8.1** (2026-10-13), Fedora 44, rootless Podman 5.8.7, Python 3.14, Node 26.
- Keycloak `cimd` = **experimental**, `spiffe` = **preview**; both are baked into the image.
- A **pre-registered** CIMD-URL client can use `clientAuthenticatorType=federated-jwt` with a `jwt-spiffe`
  assertion (verified). A **dynamically CIMD-created** client comes out as a public `none`/PKCE client.
- Not production-ready: private lab CA, script-minted SVIDs instead of SPIRE, token passthrough, static Cedar
  entities, and single-tenant assumptions. See [docs/SECURITY.md](docs/SECURITY.md).

## Credits and references

**Official specifications and docs**

- CIMD draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
- SPIFFE client auth draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/
- SPIFFE / SPIRE: https://spiffe.io/ · https://github.com/spiffe/spire
- Keycloak: https://www.keycloak.org/ · MCP authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Cedar: https://www.cedarpolicy.com/ · https://github.com/cedar-policy/cedar · `cedar-for-agents`: https://github.com/cedar-policy/cedar-for-agents
- Keycloak extension directory: https://www.keycloak.org/extensions

**Borrowed work and prior art** (see [NOTICE](NOTICE) for licenses)

- The PEP/PDP-plus-delegation pattern in `mcp/pep.py` and `cedar/` is adapted from
  [windley/openclaw-cedar-policy-demo](https://github.com/windley/openclaw-cedar-policy-demo) (MIT, © 2025 Peter
  Steinberger). No source code was copied; the demo's policy anti-patterns are reproduced only as a vulnerable
  test fixture.
- Keycloak MCP tool-surface prior art: [sshaaf/keycloak-mcp-server](https://github.com/sshaaf/keycloak-mcp-server),
  [@mgcrea/mcp-keycloak](https://github.com/mgcrea/mcp-keycloak),
  [mcp-keycloak-admin](https://github.com/mrz1880/mcp-keycloak-admin). No code copied.
- The extension matrix was derived from the public [Keycloak extensions](https://www.keycloak.org/extensions)
  directory and each project's release metadata.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.
