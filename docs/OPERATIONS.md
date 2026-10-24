# Operations runbook

Day-2 commands for the four-unit lab. Everything is user-level; no sudo. Run from anywhere unless noted.

## Service map

| Unit | Type | Restart | Logs |
|---|---|---|---|
| `keycloak-mcp-db` | quadlet (bridge) | always | `podman logs keycloak-mcp-db` |
| `keycloak-mcp-kc` | quadlet (host net) | always | `journalctl --user -u keycloak-mcp-kc` |
| `keycloak-mcp-cimd` | user service | always | `journalctl --user -u keycloak-mcp-cimd` |
| `keycloak-mcp-server` | user service | always | `journalctl --user -u keycloak-mcp-server` |

```bash
systemctl --user status keycloak-mcp-{db,kc,cimd,mcp}
systemctl --user restart keycloak-mcp-server        # after a config change
systemctl --user list-units 'keycloak-mcp-*'
```

## Health

```bash
curl -sk https://localhost:9000/health/ready            # Keycloak readiness (HTTPS mgmt)
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9000/metrics
curl -s  http://127.0.0.1:8800/healthz                  # MCP liveness
curl -s --cacert ~/.config/keycloak-mcp/certs/ca.crt \
     https://localhost:9444/client-metadata.json | jq .client_id
```

The management interface is HTTPS (same cert), so `curl -k` or `--cacert` is required; plain `http://:9000` fails.

## Backups

```bash
mkdir -p ~/kc-backups
podman exec keycloak-mcp-db pg_dump -U keycloak keycloak | gzip \
  > ~/kc-backups/keycloak-$(date +%F-%H%M).sql.gz
# restore (into an EMPTY database, e.g. after a failed upgrade)
gunzip -c ~/kc-backups/keycloak-YYYY-MM-DD.sql.gz | \
  podman exec -i keycloak-mcp-db psql -U keycloak -d keycloak
```

Config and secrets to back up too: `~/.config/keycloak-mcp/` (mode 0700) and this folder's `cimd/keys/`
(lab trust-domain key, treat as a secret).

## Routine maintenance

- **Rotate the lab CA cert** (825-day leaf): regenerate `server.crt` from `ca.crt`, then
  `systemctl --user restart keycloak-mcp-{kc,cimd}`. Keycloak reads the cert at startup; the MCP trusts the CA
  via `SSL_CERT_FILE`.
- **Rotate the SVID**: `python3 scripts/mint-svid.py mint …` writes `cimd/svid.jwt`; nothing restarts. Keep `exp`
  short; the minter defaults to minutes, not hours.
- **Change the MCP allowlist**: edit `~/.config/keycloak-mcp/allowed-clients.txt` (one URL per line), then
  `systemctl --user restart keycloak-mcp-server`. Do not use the comma env form for URLs.
- **Enable writes** (only after reading docs/SECURITY.md): set `KC_MCP_ENABLE_WRITES=1` and
  `KC_MCP_APPROVAL_PUBLIC_KEY_FILE` in `mcp.env`; the server refuses to start without the key (exit 2).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Keycloak exits `status=2`, "build time options differ" | `--optimized` with runtime `KC_DB`/health changes | Bake `ENV KC_DB=postgres KC_HEALTH_ENABLED=true` and rebuild; keep runtime env identical |
| Keycloak exits, "cannot read /etc/certs/server.key" | rootless uid mapping: host key 0600 owned by your user, container uid 1000 | `chmod 644` for a lab, or a secrets volume owned by the mapped uid |
| `/health/ready` via http fails | management interface is HTTPS | use `curl -k https://localhost:9000/health/ready` |
| MCP exits 2, `KC_MCP_CLIENT_ENTITY_MAP is not JSON` | systemd `EnvironmentFile` mangled the JSON braces | keep the map as `Environment=` in the unit (captured in `deploy/units/`), not in the env file |
| CIMD request: `invalid_client` / client not found | Keycloak cannot fetch the document (TLS trust, DNS, 404) | watch `journalctl -u keycloak-mcp-cimd` for the GET; confirm `KC_TRUSTSTORE_PATHS` includes the CA; URL must be https with a path |
| CIMD: `not trusted domain: host = …` | a URL inside the document (redirect_uri, logo, jwks) is outside the trusted domains | add that host to `cimd-allow-permitted-domains` or keep all URLs on one host |
| SVID: `Invalid token audience` | SVID `aud` is not the realm issuer | mint with `--audience $KC/realms/$REALM` |
| SVID: `Token is not active` | expired | re-mint; keep `exp` short |
| MCP: "lacks the required scope(s)" | client scopes not assigned or not requested | assign the `keycloak.*.read` scopes as default scopes; request them explicitly if needed |
| MCP tool: 403 from Keycloak | caller token has no realm-management role | assign the read-only `view-*` roles (or use an admin client for admin tools) |
| Cedar denies everything | entity map missing / client unmapped | check `--check` output `unmapped_clients`; fix the unit `Environment` map |
| Podman build: `ADD --checksum` unsupported | Podman < 4.5 | upgrade Podman |

## Upgrade checklist

1. `pg_dump` (above).
2. Read `EXTENSIONS.md` for 26.9-compatible provider versions; download + pin new sha256.
3. Rebuild image with `From …:26.9.0` and a new tag; smoke-test in a second unit on 8444 if possible.
4. Flip `Image=` in the quadlet, `daemon-reload`, `restart`, then `./scripts/verify.sh`.
5. If verification fails: restore dump, flip the tag back, restart.

## Security checks (weekly, lab)

```bash
podman ps --format '{{.Names}} {{.Status}}'                   # unexpected containers?
ss -ltn | grep -E ':(8080|8443|9000|9444|8800) '              # 9000 should be firewalled
systemctl --user show keycloak-mcp-server -p Environment      # entity map, no secrets
stat -c '%a %n' ~/.config/keycloak-mcp/*.env               # must be 600
python3 - <<'PY'
import json,pathlib
for line in pathlib.Path.home().joinpath(".local/state/keycloak-mcp/authz-audit.jsonl").read_text().splitlines()[-5:]:
    d=json.loads(line); print(d.get("decision"), d.get("tool"), d.get("policy_ids"))
PY
```
