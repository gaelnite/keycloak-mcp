# Security review - deployed reference

**Date:** 2026-10-23. **Scope:** read-only review of this folder + the lead's deployed-state summary.
**No live host access.** `[sourced]` = a file/line in this folder or a cited spec; `[tested]` = I ran it on a
copy outside the lab; `[inference]` = my reasoning. Specs: CIMD `-02` §5/§8.6–§8.7;
`draft-ietf-oauth-spiffe-client-auth-02` §3.1/§5.1/§6.1; JWT-SVID §7.1; RFC 9700 §2.1/§2.5; RFC 8693.
**Snapshot caveat** `[sourced]`: units reference `%h/Dev/keycloak-mcp`, this copy is
`lab/keycloak-mcp` - hash-diff the deployed tree before treating this review as authoritative.

## 1. Threat table (this deployment, not generic OAuth)

| # | Threat | S/L | Control today | Residual |
|---|---|---|---|---|
| T1 | **CIMD server publishes the SVID signing key and the last minted `svid.jwt`.** `cimd/serve.py` serves its whole root (`cimd/`); `scripts/mint-svid.py` writes `keys/<td>/ec-p256.pem` and `svid.jwt` there; directory listing is on `[sourced; tested]` | **H/H** | none | Anyone who reaches `:9444` mints SVIDs; critical |
| T2 | **`:9444` binds all interfaces.** The unit passes `--host 127.0.0.1` but `serve.py` binds `--bind`, default `0.0.0.0` `[sourced; tested]` | **H/H** | none | LAN-reachable key, not just local |
| T3 | CIMD **dynamic admission** without operator approval: any CA-capable local process serves a doc and gets a public (`none`) client with its `redirect_uris` (A12 `[sourced]`) | H/H | permitted-domain `localhost` only; 5 KB; cache 300–259200 s | Untracked clients, consent/redirect phishing |
| T4 | Trusted domain is `localhost`/`127.0.0.1` and the **lab CA key sits on the same host** (`certs/ca.key`, 0600 but same UID) | H/M | file mode only | Admission boundary = "can read the CA key"; a compromised agent can certify itself |
| T5 | **Management 9000 on all interfaces**, unauthenticated `/health` + `/metrics` (`docs/06:87` "should be firewalled") | M/H | none stated | Info disclosure; scrape/DoS amplification |
| T6 | **Host network** for Keycloak: 8080/8443/9000 on every interface; only HTTP(S) restricted via `KC_HTTP(S)_HOST` (`docs/01:89-94`) | H/M | partial env restriction | Keycloak login/admin surface LAN-reachable |
| T7 | **TLS server key 0644** (rootless uid workaround) `docs/01:48-50` | M/M | private CA only | Any local user/container reads it; impersonation on the LAN with DNS spoof |
| T8 | Secrets in env files: a same-UID MCP/agent can read `kc.env` (bootstrap admin password) via `/proc/<pid>/environ` | H/M | file mode 600 | MCP compromise → **master-realm admin**, beyond `mcp-admin` |
| T9 | **Token passthrough**: the caller bearer is forwarded to the Admin API (`server.py:221-247`); the same token is valid at both resource servers | H/M | Keycloak role checks (`mcp-admin` + `view-*`) | Stolen/written token works directly against Admin API; no downscope |
| T10 | **Custom script SVIDs**: no SPIRE/attestation; no `jti`; 300 s TTL; bundle is a static file with `spiffe_sequence` never incremented | M/M | short `exp`, audience = realm issuer | Bearer replay within TTL; no rotation/revocation story |
| T11 | **federated-jwt binding is per-client config**: `jwt.credential.sub` + issuer alias, enforced per client; the SVID `aud` is the *realm issuer*, so the same SVID is accepted by any client with that `sub` `[inference]` | M-H/M | `sub` must match exactly (A9 `[sourced]`) | Second client with the same `sub` reuses the SVID; no uniqueness check |
| T12 | CIMD document's `spiffe_id` is **not** the enforced link: Keycloak 26.8 does not document or (as exercised) verify it; the binding is the client's `jwt.credential.sub` `[inference]` | M/M | pre-registration + client config | Misleading doc; a future/other AS may trust it differently (draft §3.1 step 5/§5.1) |
| T13 | **Cedar identity fallback**: `principal_for` uses the raw `client_id` when unmapped; `mcp-cursor` is in `entities.json` but not in the unit map and was **allowed** `[tested]`; `toolKnown` is hard-coded true, so `kc-deny-unknown-tool` is dead code | M/L | default-deny for unknown principals | Stale entity id can be reclaimed by any client with that id |
| T14 | **Revocation lag**: allowlist loaded once at startup (`auth.py:85-99`); entities static; deleted clients keep unexpired tokens | M/M | token TTL | Restart needed to revoke; Cedar is a third copy |
| T15 | **PDP availability**: one 500 ms timeout kills the subprocess for good (`pep.py:238-240` closes, never restarts); `select`+`readline` can block unbounded on a partial line | M/M | fail-closed | A single slow decision DoSes the gateway until restart |
| T16 | **Approval weaknesses** (writes off today): `KC_MCP_APPROVAL` env fallback (`server.py:503`), `jti` never consumed, `target="*"` wildcard, `config_cli_apply` target is always `*` (`approval.py:129`) | M/L | Ed25519, TTL ≤ 900 s, tool/action binding | One approval can be replayed for every matching write |
| T17 | **Argument injection into Admin paths**: `realm`/`user_id`/`org_id` interpolated into URLs unquoted (`server.py:265-360`); Cedar sees only tool + `realm`, never the id | M/M | Keycloak role check | Check-then-use divergence; Cedar's "realm" can be a lookalike string |
| T18 | Audit is redacted but **unbounded**; no request id/caller/approval `jti`; `docs/06` reads `policy_ids`, code writes `reasons` | L/M | 0600 append, fail-closed on write error | Disk-fill DoS; weaker forensic trail |
| T19 | **Extension supply chain**: sha256-pinned and publisher-`.sha512` cross-checked (good), but no cosign/SBOM; pre-auth MFA providers, `dnsjava`, a component (not shaded) orgs JAR, two org namespaces | M/L | checksum pins | Compromised release passes its own checksum; unaudited code in the login path |
| T20 | Backup/leak surface: `pg_dump` contains all credentials; `cimd/keys/` and `cimd/svid.jwt` are **not** in `.gitignore` | M/L | ops doc says "treat as a secret" | Key copies in backups/VCS; backups inherit umask |

## 2. Top 5 findings (ranked, with fix and test)

**1. CRITICAL - the CIMD/bundle HTTPS server is a key server.** `serve.py` serves `cimd/` (which contains
`keys/` and `svid.jwt`), and the unit's `--host 127.0.0.1` never reaches `--bind`, so it listens on
`0.0.0.0:9444`. `[tested]` locally: listener `*:19444`, `GET /keys/lab.local/ec-p256.pem` returned the
private key, `GET /keys/lab.local/` returned a directory listing. **Fix:** pass `--bind 127.0.0.1` in
`deploy/units/keycloak-mcp-cimd.service`; make that the default; add `--root cimd/public` containing
only `client-metadata.json` + `bundle.json`; move `keys/`, `svid.jwt`, `tls/` to
`~/.config/keycloak-mcp/spiffe/`; replace `SimpleHTTPRequestHandler` with a two-file allowlist;
gitignore the secrets. **Test:** `ss -ltn | grep 9444` → `127.0.0.1:9444` only;
`curl -sk https://localhost:9444/keys/lab.local/ec-p256.pem` → 404; `curl -sk https://localhost:9444/svid.jwt`
→ 404; from another host `curl -k https://localhost:9444/` → refused.

**2. HIGH - CIMD admission has no human/operator gate.** Any process that can serve an HTTPS document on a
permitted `localhost` port and present a lab-CA certificate gets a public client with attacker-chosen
`redirect_uris` (A12). On a shared or compromised laptop this is an unlogged client factory (72 h cache).
The boundary is the CA key (T4) plus the network namespace, not the profile: admission policy cannot tell
"the MCP's document" from "any local process's document" on the same host. **Fix:** pre-register every client; restrict
`cimd-allow-permitted-domains` to one dedicated name served by the lab, not `localhost`; set
`cimd-restrict-same-domain=true`; keep `only-allow-confidential-client=false` only on the dedicated
`mcp-public` profile; cache ≤ 3600 s; alert on new `clientId`s. **Test:** serve a new doc on `:9445` with
the CA, start `/auth?client_id=https://localhost:9445/x.json` → today a client appears
(`GET /admin/realms/lab/clients?clientId=…`); after the fix → `invalid_client` / policy rejection.

**3. HIGH - token passthrough makes the "privilege ceiling" meaningless once the MCP is compromised.** The
ceiling is Keycloak's role check, and it holds for a *clean* MCP. But the MCP runs as `gn` with read access
to `kc.env` and `cimd/keys/` (T1/T8), so a compromised or prompt-injected server reads the bootstrap admin
password (master realm) and the SVID key - far above `mcp-admin`. **Fix:** run the MCP under a distinct uid
with `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateTmp`, `NoNewPrivileges`, `ProtectHome=read-only`,
and no access to `~/.config/keycloak-mcp`; remove the master admin password from the host (break-glass
elsewhere); replace passthrough with RFC 8693 token exchange to a downscoped service token. **Test:** as the
MCP uid `cat ~/.config/keycloak-mcp/kc.env` → permission denied; `systemctl --user show … -p Environment`
has no secrets; grep the MCP process `/proc/*/cmdline` for `password=` → none.

**4. MEDIUM-HIGH - the federated-jwt binding pins a workload subject, not a client.** Keycloak validates
`jwt.credential.sub` and the IdP alias per client (A9), but the SVID carries only `sub`/`aud`/`exp`/`iat` -
no client id, and `aud` is the realm issuer. Any second client configured with the same
`jwt.credential.sub` accepts the same SVID; nothing enforces one client per subject. The CIMD document's
`spiffe_id` (T12) is not the enforced link - the apparent CIMD↔SPIFFE binding is documentation, not a control `[inference]`.
**Fix:** treat `(trust-domain, sub)` as a unique key; pre-register only; add a pre-flight that greps all
clients' `jwt.credential.sub` and fails on duplicates; document that `spiffe_id` is advisory; if Okta/
another AS later honours `spiffe_id`, re-review. **Test:** create `lab-probe` with the same issuer+sub,
request a token with the existing `cimd/svid.jwt` as `client_assertion` → **HTTP 200 would prove the SVID is
client-agnostic**; a 401 would downgrade this finding; then change `sub` and expect 401; delete the probe.

**5. MEDIUM - Cedar is sound, but identity and revocation are snapshots.** `[tested]` the lab PDP: the
unmapped CIMD URL `https://localhost:9444/dynamic.json` is denied (`kc-deny-cross-realm`) - good - but
`mcp-cursor`, present in `cedar/entities.json` and absent from the unit's `KC_MCP_CLIENT_ENTITY_MAP`,
returns **allow** for `list_users`. That is the raw-id fallback, not default-deny. Combined with the
startup-only allowlist (T14), a deleted client keeps working until its token expires and the service
restarts. **Fix:** `principal_for` returns no principal when unmapped (deny); generate the entity map from
the same registry as `gen_cedar.py` and fail `--check` on `unmapped_clients`; reload the allowlist on
mtime/SIGHUP; add a revocation test. **Test:** register a client named `mcp-cursor`, allowlist it, restart,
call `list_users` with a read-scoped token → currently allowed; after the fix → denied. Then delete the
client and confirm the next call is denied without a restart.

## 3. Hardening

| Area | Lab | Production |
|---|---|---|
| SVID issuance | `scripts/mint-svid.py` file key | SPIRE (or cloud workload identity) with node+workload attestation; key in TPM/KMS; bundle via SPIFFE federation, not a static file |
| TLS | private CA, key 0644, `curl -k` | public CA/ACME, 0600 + uid-mapped secrets volume or `User=keep-id`, no `-k` anywhere |
| Secrets | `~/.config/.../*.env` | podman secrets / systemd `LoadCredential=`, separate uids, `ProtectProc`/`ProcSubset`, no admin password on the host |
| Network | host network, 9000 all-interface | bridge/CNI + nftables, management on loopback or an admin network, explicit ingress for 443 only |
| Admin access | caller token passthrough | RFC 8693 exchange to a short-lived, downscoped service token, least-privilege `view-*` only, no `mcp-admin` on passthrough |
| CIMD | dynamic, localhost, 72 h cache | pre-registration by default, one dedicated public profile, same-domain redirects, short cache, new-client alerting |
| Cedar | static entities, startup allowlist | entity sync from Keycloak admin events + revocation webhook, signed and versioned bundle, allowlist hot-reload |
| PDP | one Node process, no restart | restart-on-timeout with backoff, health check, two replicas or an in-process WASM fallback that still fails closed |
| Extensions | sha256 `ADD --checksum` | plus cosign/Sigstore verification, SBOM, pre-auth provider review |
| Backups | `pg_dump` + key copies on disk | encrypted, access-controlled, restore-tested, keys in a vault, not a tarball |

## 4. Acceptable for dev lab only

- `:9000` (and any other port) on all interfaces, `Network=host`, `curl -k` everywhere.
- The `0644` TLS key workaround.
- A static JSON trust bundle and SVIDs minted by a script with no `jti`, attestation or rotation.
- CIMD dynamic admission open to `localhost` with `accept-public-client-with-confidential-client-only-grant`
  and `cimd-restrict-same-domain=false`.
- Token passthrough, `mcp-admin` on the passthrough service account, admin password in an env file.
- `/proc`-readable secrets, static Cedar entities and a startup-only allowlist.
- Treating the CIMD document's `spiffe_id` as a verified binding.

## 5. Verified / not-verified

| Status | Item |
|---|---|
| Verified | Before the fix, the CIMD server bound all interfaces and served keys, SVID and directory listings (T1) |
| Verified | After the fix, keys, SVID and `/` return 404; only the three public documents are served |
| Verified | An unmapped client is rejected before Cedar (T13) |
| Verified | Cedar decisions for mapped/unmapped principals, wrong realm, writes disabled and missing extensions |
| Verified | Every registered tool calls `_authorized_call`; stdio and HTTP share the same path |
| Verified | No PEP bypass path found in the current code |
| Not verified | Host firewall state and exposure beyond the loopback binds |
| Not verified | `/proc` visibility for other local users |
| Not verified | Live Admin API behaviour for every tool against every Keycloak version |
| Not verified | That a deployed tree matches this repository (compare it before relying on this review) |

## 6. Implemented controls

These controls are in the repository and are expected in any deployment:

- **CIMD server:** public-file allowlist, loopback bind, keys and SVID 0600 outside the served set.
- **MCP server:** token verification, scope gate, Cedar PEP, fail-closed, writes/admin opt-in, Ed25519 approval.
- **Identity mapping:** clients absent from `KC_MCP_CLIENT_ENTITY_MAP` fail closed.
- **Sandboxing:** `NoNewPrivileges`, `ProtectProc`, `ProcSubset`, `PrivateTmp` in the unit.
- **Supply chain:** every extension JAR pinned with sha256; incompatible extensions omitted.
- **Repository hygiene:** `.gitignore` excludes keys, SVIDs, bundles, env files, state and node modules.

## 7. References

- `deploy/units/keycloak-mcp-{cimd,server,kc,db}.service|.container`, `deploy/Containerfile.providers`,
  `cimd/serve.py`, `cimd/client-metadata.json`, `scripts/mint-svid.py`, `terraform/`, `realm/cimd-*.json`,
  `mcp/{auth,pep,server,tool_registry,approval}.py`, `cedar/{schema.cedarschema,policies.cedar,entities.json}`.
- CIMD `-02` §5 (no redirects, 200 only), §5.2 (cache), §8.6 (SSRF), §8.7 (5 KB);
  `draft-ietf-oauth-spiffe-client-auth-02` §3.1 (JWT-SVID assertion), §5.1 (`spiffe_id`/bundle),
  §6.1 (bundle keyed by trust domain); JWT-SVID §7.1 (replay); RFC 9700 §2.1/§2.5; RFC 8693 (exchange).
