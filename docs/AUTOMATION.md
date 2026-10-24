# Automation: one command up and down

Ansible provisions the host and orchestrates the lifecycle. Terraform owns the Keycloak configuration. Together
they replace the manual sequence in [DEPLOYMENT.md](DEPLOYMENT.md) for day-to-day use.

## Prerequisites

Podman 4.5+ (rootless), Python 3.11+, Node 22+, Terraform 1.6+ and Ansible 2.15+. The playbook checks for them
and fails early.

## Quick start

```bash
git clone https://github.com/gaelnite/keycloak-mcp.git ~/Dev/keycloak-mcp
cd ~/Dev/keycloak-mcp
make up
```

`make up` performs, in order:

1. creates `~/.config/keycloak-mcp` with mode 0711 and a `certs` directory readable by the uid-mapped container;
2. generates `secrets.json` (database and bootstrap admin passwords) on first run only;
3. creates a local CA and a server certificate for `localhost` and `127.0.0.1`;
4. builds the Keycloak image with the pinned extensions;
5. renders the systemd and quadlet units, environment files, CIMD documents and client policies;
6. starts PostgreSQL and Keycloak and waits for readiness;
7. installs the MCP Python and Cedar dependencies;
8. applies the Terraform module (realm, scopes, role, client, audience mapper, service-account roles, SPIFFE IDP);
9. applies the CIMD client policy documents through the Admin API;
10. mints the lab SVID, starts the CIMD endpoint and the MCP server;
11. runs `scripts/verify.sh` and prints the result.

The run is idempotent. Re-running `make up` updates files, restarts the CIMD endpoint and the MCP server, and
leaves the database and Terraform state intact.

## Teardown

```bash
make down
```

This runs `terraform destroy` while Keycloak is still up, stops and disables the units, removes the containers and
volumes, removes the generated configuration and state, and reloads systemd. The repository and the built image
are kept. Set `remove_image=true` to delete the image as well, or `keep_volumes=true` / `keep_config=true` to keep
data and configuration.

## Configuration

Defaults live in `ansible/playbooks/group_vars/all.yml`. Override any value with `-e`, for example to run beside an
existing stack on different ports:

```bash
make up ANSIBLE_ARGS="-e kc_http_port=8081 -e kc_https_port=8543 -e kc_management_port=9001 \
  -e cimd_port=9544 -e mcp_port=8900 -e db_port=5433"
make down ANSIBLE_ARGS="-e kc_http_port=8081 -e kc_https_port=8543 -e kc_management_port=9001 \
  -e cimd_port=9544 -e mcp_port=8900 -e db_port=5433"
```

| Variable | Default | Meaning |
|---|---|---|
| `stack_name` | `keycloak-mcp` | prefixes container, volume and unit names |
| `kc_http_port` | `8080` | HTTP port |
| `kc_https_port` | `8443` | HTTPS and issuer port |
| `kc_management_port` | `9000` | health and metrics port |
| `cimd_port` | `9444` | CIMD document and bundle port |
| `mcp_port` | `8800` | MCP streamable HTTP port |
| `db_port` | `5432` | PostgreSQL port published on loopback |
| `realm` | `lab` | Keycloak realm |
| `trust_domain` | `spiffe://lab.local` | SPIFFE trust domain |
| `spiffe_subject` | `spiffe://lab.local/workload/mcp-client` | expected SVID subject |
| `force_build` | `false` | rebuild the Keycloak image even if present |
| `run_verify` | `true` | run the end-to-end checks at the end |
| `remove_image` | `false` | also delete the image on teardown |
| `keep_volumes` | `false` | keep database and Keycloak volumes on teardown |
| `keep_config` | `false` | keep the generated configuration on teardown |

## What Ansible does not do

Ansible does not manage Keycloak objects. Realm, client, scopes, role mappings and the SPIFFE identity provider
are Terraform resources. CIMD client policies stay as declarative JSON because the provider cannot express their
typed values; see [TERRAFORM.md](TERRAFORM.md).

## Safety notes

- The playbook runs as your user with rootless Podman. It does not use sudo.
- It writes only under `~/.config/keycloak-mcp`, `~/.local/state/keycloak-mcp`, the systemd user directories and the
  repository's ignored build artefacts.
- `make down` deletes the generated configuration and volumes by default. Keep them with `keep_config=true` and
  `keep_volumes=true` if you need the data.
- The generated TLS key is mode 0644 because rootless uid mapping makes a 0600 key unreadable inside the
  container. See [SECURITY.md](SECURITY.md) for the production replacement.
