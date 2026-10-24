# Deployment, Keycloak 26.8.1 on Podman

How this project is built and how to rebuild it. Everything is rootless Podman under user `gn`; there is no system-level
sudo dependency. Verified on Fedora 44, Podman 5.8.7, Keycloak 26.8.1 (2026-10-13 image).

## 1. Host prerequisites

```bash
podman --version            # 5.8.7 (ADD --checksum needs >= 4.5)
loginctl show-user gn --property=Linger   # Linger=yes (already set)
ss -ltn | grep -E ':(8080|8443|9000|9444|8800) ' || true
```

If linger were off: `loginctl enable-linger gn` (this is the only step that may need admin rights on some hosts).

Paths used (all under the user's home, nothing system-wide):

```text
~/Dev/keycloak-mcp/           # this repository
~/.config/keycloak-mcp/               # runtime config + secrets, mode 0700
  certs/{ca.crt,ca.key,server.crt,server.key}
  db.env kc.env mcp.env allowed-clients.txt
~/.config/containers/systemd/             # quadlets (rootless)
~/.config/systemd/user/                   # plain user units (cimd, mcp)
```

## 2. Local CA and TLS

CIMD requires https, and Keycloak must trust the certificate of the client-metadata server for its outbound fetch.
One CA, one server cert with SANs for everything the lab uses:

```bash
cd ~/.config/keycloak-mcp/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=Keycloak MCP Lab Local CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -sha256 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
cat > san.cnf <<'EOF'
subjectAltName=DNS:localhost,DNS:keycloak.local,DNS:host.containers.internal,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -sha256 \
  -extfile san.cnf -out server.crt
chmod 600 ca.key server.key; chmod 644 ca.crt server.crt
```

**Rootless UID mapping gotcha:** the Keycloak image runs as uid 1000, which maps to a subordinate uid on the host.
A host key file owned by `gn` with mode `0600` is therefore unreadable inside the container. This lab uses `0644`
for the server key and documents the production fix (a secrets volume owned by the mapped uid, or `User=keep-id`).

## 3. Secrets

```bash
umask 077
cat > ~/.config/keycloak-mcp/db.env <<EOF
POSTGRES_DB=keycloak
POSTGRES_USER=keycloak
POSTGRES_PASSWORD=$(openssl rand -hex 16)
EOF
cat > ~/.config/keycloak-mcp/kc.env <<EOF
KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 12)
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/keycloak
KC_DB_USERNAME=keycloak
KC_DB_PASSWORD=<same as db.env>
KC_HOSTNAME=https://localhost:8443
KC_HOSTNAME_STRICT=false
KC_HTTP_ENABLED=true
KC_HTTP_HOST=127.0.0.1
KC_HTTPS_HOST=127.0.0.1
KC_HTTPS_PORT=8443
KC_HTTPS_CERTIFICATE_FILE=/etc/certs/server.crt
KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/certs/server.key
KC_TRUSTSTORE_PATHS=/etc/certs/ca.crt
KC_LOG_LEVEL=INFO
EOF
chmod 600 ~/.config/keycloak-mcp/{db.env,kc.env}
```

`KC_TRUSTSTORE_PATHS` makes Keycloak trust the lab CA for its outbound CIMD/bundle fetches; without it the fetch
fails with an opaque error and the CIMD request looks like "client not found".

## 4. Quadlets

`deploy/units/keycloak-mcp-{db,kc}.container` are the captured files. Key points:

- **PostgreSQL** is on a bridge network with a named volume and `PublishPort=127.0.0.1:5432:5432`.
- **Keycloak uses `Network=host`.** That is deliberate: CIMD and the SPIFFE bundle are served on the *host's*
  loopback, and inside a bridge container `localhost` would be the container. Host networking makes
  `https://localhost:9444/...` resolve identically for Keycloak and for local clients, so one `client_id` string
  works everywhere. The trade-off is that 8080/8443/9000 bind all host interfaces, restricted with
  `KC_HTTP_HOST`/`KC_HTTPS_HOST` for HTTP(S), and documented as a lab gap for the management port.
- `EnvironmentFile=%h/.config/keycloak-mcp/kc.env`; no secrets in the unit files.
- `Restart=always`, so a crash restarts; with linger on, the user units start at boot.

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/units/keycloak-mcp.network ~/.config/containers/systemd/   # if not already present
cp deploy/units/keycloak-mcp-{db,kc}.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user enable --now keycloak-mcp-db.service keycloak-mcp-kc.service
```

## 5. Building the extension image (important)

The image is `localhost/keycloak-mcp:26.8.1`, built from `deploy/Containerfile.providers`. Two build-time
details matter because the container runs with `--optimized`:

```dockerfile
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build --features=cimd,spiffe --metrics-enabled=true
```

- `kc.db`, health and metrics are **build-time** options. Passing them only at runtime with `--optimized` makes
  Keycloak exit with `status=2` and "build time options have values that differ from what is persisted".
- Features are baked in. Runtime `KC_FEATURES` must not be set to a different list.
- Provider JARs go into `/opt/keycloak/providers`; `kc.sh build` registers their SPIs.

```bash
cd ~/Dev/keycloak-mcp
podman build -t localhost/keycloak-mcp:26.8.1 -f deploy/Containerfile.providers .
```

Startup with the optimized image is ~50 s cold; a rebuild (no `--optimized`) is ~2 min.

## 6. Feature flags

`--features=cimd,spiffe` enables the CIMD (experimental) and SPIFFE (preview) providers without the whole
`preview` set. Discovery then returns `client_id_metadata_document_supported: true`.

## 7. Realm provisioning

Terraform creates the realm, scopes, role, client, audience mapper, service-account mappings and SPIFFE IDP:

```bash
export TF_VAR_admin_password=...
terraform -chdir=terraform init && terraform -chdir=terraform apply
KEYCLOAK_ADMIN_PASSWORD="$TF_VAR_admin_password" make policies
```

CIMD client policies come from `realm/cimd-*.json`; see [TERRAFORM.md](TERRAFORM.md).

## 8. Upgrade and rollback

1. Change `FROM ...:<new>`, check compatibility in [EXTENSIONS.md](EXTENSIONS.md), rebuild with a new tag.
2. Back up: `podman exec keycloak-mcp-db pg_dump -U keycloak keycloak > ~/kc-backup-$(date +%F).sql`
3. Point the quadlet `Image=` at the new tag, reload and restart. Keycloak migrates automatically.
4. Roll back with the dump and the old image tag.
