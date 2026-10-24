# Terraform provisioning

Realm, client, scopes, roles and the SPIFFE identity provider are managed with the official
[Keycloak Terraform provider](https://registry.terraform.io/providers/keycloak/keycloak/latest), not with imperative
scripts. The configuration is reviewable in a pull request, `terraform plan` shows the diff, and re-running is
idempotent.

## What Terraform manages

`terraform/main.tf` creates:

- the realm (`lab` by default) with a 300 s access-token lifespan;
- 14 client scopes: `mcp.read`, `mcp.write` and the twelve `keycloak.*.read` scopes used by the tool registry;
- the `mcp-admin` realm role;
- the SPIFFE identity provider (`keycloak_spiffe_identity_provider`, provider id `spiffe`);
- the CIMD client: its `client_id` is the HTTPS metadata URL, `client_authenticator_type = "federated-jwt"`,
  with `jwt.credential.issuer` and `jwt.credential.sub` in `extra_config`;
- the audience mapper for the MCP resource;
- default client scopes, the `mcp-admin` service-account role, and the read-only `realm-management` roles.

The module was applied against Keycloak 26.8.1: 30 resources, then an SVID token request against the new realm
returned 200 with `azp` set to the CIMD URL, the MCP audience present, and `keycloak.realms.read` in scope.

## What Terraform does not manage

**CIMD client policies.** `keycloak_realm_client_policy_profile` stores executor configuration as strings, while
the CIMD executor needs typed booleans and arrays (`false`, `["localhost", "127.0.0.1"]`). The provider drops or
stringifies those values, and Keycloak rejects the request. The profiles and policies therefore live as declarative
JSON in `realm/cimd-profile.json` and `realm/cimd-policy.json`, applied by `make policies` through the Admin API.
This is data, not logic: review the JSON in the pull request. Track the provider issue at
[keycloak/terraform-provider-keycloak#1741](https://github.com/keycloak/terraform-provider-keycloak/issues/1741).

Also outside Terraform: TLS certificates, the SVID minter, the CIMD file server and the verification script. Those
are host utilities, not Keycloak configuration. They stay small and single-purpose:

| Path | Why it is not Terraform |
|---|---|
| `cimd/serve.py` | serves the HTTPS metadata document and bundle; no Keycloak API |
| `scripts/mint-svid.py` | creates a lab SVID and bundle; replaced by SPIRE in production |
| `scripts/verify.sh` | end-to-end acceptance test across Keycloak, CIMD and the MCP server |

## Usage

```bash
export TF_VAR_admin_password="$(grep KC_BOOTSTRAP_ADMIN_PASSWORD ~/.config/keycloak-mcp/kc.env | cut -d= -f2)"

terraform -chdir=terraform init
terraform -chdir=terraform plan
terraform -chdir=terraform apply
KEYCLOAK_ADMIN_PASSWORD="$TF_VAR_admin_password" make policies
```

Or use the Make targets: `make init`, `make plan`, `make apply`, `make policies`.

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `keycloak_url` | `https://localhost:8443` | Keycloak base URL, no `/admin` suffix |
| `admin_username` | `admin` | master-realm admin |
| `admin_password` | none, use `TF_VAR_admin_password` | sensitive |
| `admin_client_id` | `admin-cli` | password-grant client |
| `realm` | `lab` | realm to create and manage |
| `cimd_client_id` | `https://localhost:9444/client-metadata.json` | value used as the OAuth client id |
| `mcp_audience` | `https://localhost:8800/mcp` | audience added to access tokens |
| `spiffe_trust_domain` | `spiffe://lab.local` | SPIFFE trust domain |
| `spiffe_bundle_endpoint` | `https://localhost:9444/bundle.json` | bundle the identity provider fetches |
| `spiffe_subject` | `spiffe://lab.local/workload/mcp-client` | expected SVID `sub` |
| `tls_insecure_skip_verify` | `true` | development only, for the private CA |

See `terraform/terraform.tfvars.example`.

## Provider notes

- **Password grant:** the provider authenticates with `admin-cli` and the bootstrap admin. For a shared deployment,
  create a dedicated service account and use the client-credentials grant instead.
- **`initial_login = false` and pinned `keycloak_version`:** some Keycloak builds return an incomplete
  `/admin/serverinfo`; pinning the version avoids a provider preflight dependency on that endpoint.
- **`tls_insecure_skip_verify = true`** is for the lab certificate. In production, pass the CA through
  `root_ca_certificate` and set the flag to `false`.
- **State:** the default local state is fine for a single lab. Use a remote backend with locking for a team.
- **Imports:** the client-policy resources do not support import. For an existing realm, import the realm, client,
  scopes and identity provider by their documented IDs, then apply the policy JSON separately.
- **Ordering:** `make policies` requires the realm and the client policy profile. Run it after `terraform apply`.

## Verification

```bash
terraform -chdir=terraform output
KEYCLOAK_ADMIN_PASSWORD="$TF_VAR_admin_password" make policies
./scripts/verify.sh
```

The verification script checks discovery, health, the CIMD document and bundle, a positive SVID token, a
wrong-audience rejection, the MCP 401 path and one real `tools/call`.
