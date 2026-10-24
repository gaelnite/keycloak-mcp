# AuthN on Keycloak 26.8.1: SPIFFE JWT-SVID client auth + Client ID Metadata Document

Target: Keycloak **26.8.1**, rootless, HTTPS on localhost with a private lab CA, realm `lab`. `[S#]` = sourced (URL in Sources); `[I]` = inference, not stated by a source. Items marked **UNVERIFIED** have not run against a live host, see §8.

## 1. What 26.8.1 ships

| Capability | Feature name | Maturity | Default | Enable |
|---|---|---|---|---|
| Federated client authentication (framework) | `client-auth-federated` | **Supported** | on |, |
| SPIFFE identity provider (`jwt-spiffe` assertions) | `spiffe` | **Preview** | **off** | `--features=spiffe` |
| Client ID Metadata Document | `cimd` | **Experimental** | **off** | `--features=cimd` |
| Client policies (prerequisite for CIMD) | `client-policies` | supported | on |, |

Sources: [S1] `client-auth-federated:v1` sits under *Supported* while `spiffe:v1` ("SPIFFE trust relationship provider") sits under *Preview*, defined as "disabled by default and not recommended for use in production"; [S2] CIMD "is an experimental feature… start Keycloak with `--features=cimd`"; [S3] "SPIFFE is Preview and is not fully supported."

## 2. Prerequisites

1. **HTTPS everywhere.** The `client_id` must be `https`, and clients only discover the flag over TLS.
2. **Certificates with real SANs** for `kc.lab.local` and `cimd.lab.local`; both must resolve via `/etc/hosts` or dnsmasq on the host.
3. **Keycloak must trust the lab CA for its own outbound fetch:** `--truststore-paths=/etc/ssl/lab/lab-ca.pem`, a list of PKCS#12 (`.p12/.pfx/.pkcs12`), PEM files, or directories containing them, used as the system truststore [S5]. An untrusted CIMD server cert surfaces as an opaque fetch failure, the #1 lab failure mode. [I]
4. `bundleEndpoint` is validated with `checkUrl(realm.getSslRequired(), …)` [S6], so a realm with SSL required rejects `http://` bundle endpoints. Use `https://` for both CIMD and bundle.

## 3. Start Keycloak

```bash
bin/kc.sh start --features=cimd,spiffe --truststore-paths=/etc/ssl/lab/lab-ca.pem \
  --hostname=https://kc.lab.local:8443 \
  --https-certificate-file=/etc/ssl/lab/kc.pem --https-certificate-key-file=/etc/ssl/lab/kc-key.pem
```
Individual flags are `--features=cimd` / `--features=spiffe` [S1][S2]; the comma form is standard Keycloak syntax. [I, if it errors, pass both flags separately.]

## 4. CIMD: client profile + policy (without both, nothing is fetched)

The feature flag alone does nothing: a **profile** holds the `client-id-metadata-document` executor, and a **policy** holds the `client-id-uri` condition that triggers it [S2].

**Realm settings → Client policies → Profiles → Create** (`cimd-profile`), add executor **`client-id-metadata-document`**:

| UI option | Config key [S7] | Lab value | Note |
|---|---|---|---|
| Allow http scheme | `cimd-allow-http-scheme` | `false` | must stay OFF in production |
| Trusted domains | `cimd-allow-permitted-domains` | `["lab.local"]` | wildcards ok; **empty = all domains denied** |
| Restrict same domain | `cimd-restrict-same-domain` | `false` | ties client_id/redirect/URL props to one domain |
| Required properties | `cimd-required-properties` | `[]` | e.g. `["client_name"]` to force it |
| Only Allow Confidential Client | `only-allow-confidential-client` | `false` | if ON: needs `jwks`/`jwks_uri` + `private_key_jwt`/`tls_client_auth` |
| Accept Public Client w/ Confidential-only Grants | `accept-public-client-with-confidential-client-only-grant` | `true` | drops unusable grants instead of rejecting the doc |
| Resource indicator allow list | `cimd-resource-indicator-allow-list` | `["https://mcp.lab.local/mcp"]` | needs `resource-indicators`; adds the `aud` mapper |

**Policies → Create** (`cimd-policy`), add condition **`client-id-uri`**: `URI scheme` = `["https"]` (`client-id-uri-scheme`), `Trusted domains` = `["lab.local"]` (`client-id-uri-allow-permitted-domains`, **empty means the condition never matches**) [S8]. Attach `cimd-profile` under *Associated client profiles*.

**Keycloak is stricter than the draft** [S2]: `https`, a path component, no dot-segments, no fragment, no userinfo, and it turns the draft's `SHOULD NOT` on query strings into a **hard rejection**. Documents are capped at 5 KB by default.

**System-wide limits** (SPI options, not in the console) [S2][S7]:

```bash
--spi-client-policy-executor--client-id-metadata-document--min-cache-time=300
--spi-client-policy-executor--client-id-metadata-document--max-cache-time=259200
--spi-client-policy-executor--client-id-metadata-document--upper-limit-metadata-bytes=5000
```
Defaults 300 s / 259 200 s (3 d) / 5000 B. Pattern is `--spi-<spi>--<provider-id>--<property>`; the docs' rendered line contains a typographic dash, use ASCII double hyphens. [I]

**Confirm the flag is advertised:**

```bash
curl -s https://kc.lab.local:8443/realms/lab/.well-known/openid-configuration \
  | jq .client_id_metadata_document_supported      # -> true, only with cimd on
```
[S9] `OIDCWellKnownProvider` sets it **iff** `Profile.Feature.CIMD` is enabled, and injects `none` into `client_auth_methods_supported` if absent. The same field appears on `.well-known/oauth-authorization-server`. [I]

## 5. SPIFFE identity provider

Provider id `spiffe`; config keys are exactly `trustDomain` and `bundleEndpoint`; `trustDomain` must match `spiffe://[a-z0-9.\-_]*`, the bare trust domain, **no path** [S6]. **Identity providers → Add provider → SPIFFE** [S3]:

| Setting | Lab value |
|---|---|
| Alias | `spiffe-lab`, this alias is what links a client to the provider |
| SPIFFE Trust Domain | `spiffe://lab.local` |
| SPIFFE Bundle Endpoint | `https://cimd.lab.local:8444/bundle.json` |

**Admin API equivalent** [I, IdentityProviderRepresentation shape; verify with a GET after creating one in the console]:

```bash
kcadm.sh create identity-provider/instances -r lab <<'JSON'
{"alias":"spiffe-lab","displayName":"SPIFFE lab","providerId":"spiffe","enabled":true,
 "config":{"trustDomain":"spiffe://lab.local","bundleEndpoint":"https://cimd.lab.local:8444/bundle.json","allowedClockSkew":"30"}}
JSON
```
The endpoint may be a SPIFFE bundle **or** an OIDC JWKS endpoint [S3]. Keycloak's loader expects top-level `spiffe_sequence` + `spiffe_refresh_hint` and no `alg` on the JWK [S10], `scripts/mint-svid.py` emits exactly that.

## 6. The client (federated assertion)

Client authenticator type **`federated-jwt`**, the provider id, not the feature name `client-auth-federated` [S11], plus two attributes [S11]: `jwt.credential.issuer` = "alias of an identity provider set up in this realm" → `spiffe-lab`; `jwt.credential.sub` = "External clientId (subject) as provided by the identity provider" → `spiffe://lab.local/workload/mcp-client`.

```bash
kcadm.sh create clients -r lab <<'JSON'
{"clientId":"https://cimd.lab.local:8444/client-metadata.json","protocol":"openid-connect","enabled":true,
 "publicClient":false,"clientAuthenticatorType":"federated-jwt","standardFlowEnabled":false,
 "implicitFlowEnabled":false,"directAccessGrantsEnabled":false,"serviceAccountsEnabled":true,
 "attributes":{"jwt.credential.issuer":"spiffe-lab","jwt.credential.sub":"spiffe://lab.local/workload/mcp-client"}}
JSON
```
[S3]: SVIDs "can be re-used multiple times", keep `exp` short and stay TLS-only.

## 7. Run it

```bash
# 1. CIMD + bundle over HTTPS (lab CA certs, or --selfsigned for a throwaway)
./cimd/serve.py --host cimd.lab.local --port 8444 \
                --cert /etc/ssl/lab/cimd.pem --key /etc/ssl/lab/cimd-key.pem

# 2. Generate the fake trust domain (writes cimd/bundle.json, cimd/svid.jwt, cimd/keys/)
./scripts/mint-svid.py init --trust-domain spiffe://lab.local

# 3. Acceptance run: discovery flag, CIMD doc, bundle, positive token request,
#    then wrong-aud / wrong-sub / expired / wrong-assertion-type negatives.
KC=https://kc.lab.local:8443 REALM=lab SPIFFE_ID=spiffe://lab.local/workload/mcp-client ./scripts/authn-demo.sh
```

`scripts/mint-svid.py` is stdlib-only (P-256 ECDSA inline; no `cryptography`/`PyJWT`) because the lab host may be bare. `selftest` checks sign/verify plus the curve-order identities; the emitted signature was independently confirmed with `openssl dgst -sha256 -verify` → **Verified OK** on the authoring host.

## 8. Open questions / UNVERIFIED without the host

1. **Does a CIMD-created client get `federated-jwt`?** Nothing in the 26.8 docs joins the two features. CIMD derives a client from `token_endpoint_auth_method`; SPIFFE needs `clientAuthenticatorType=federated-jwt` + `jwt.credential.sub`, which CIMD has no standard field for. **Assume pre-registration for the SPIFFE path**; use CIMD as the metadata/discovery test. The `scripts/authn-demo.sh` probe answers it empirically.
2. **Does Keycloak enforce `aud` == AS issuer** for `jwt-spiffe` (draft §3.1 step 3)? The demo's "wrong aud" case answers this.
3. **Exact Admin API JSON encoding of list-valued policy config**, Keycloak stores JSON-in-string (`"[\"lab.local\"]"`). [I] Create once in the console, then `GET /admin/realms/lab/client-policies/profiles` and copy the wire form.
4. **Bundle compatibility**, our `spiffe_sequence`/`spiffe_refresh_hint`, no-`alg` shape is untested against 26.8's loader. Also unverified: `--features=cimd,spiffe` comma syntax, and whether `spiffe` needs `kc.sh build`.

**Lab results:** the deployed verification and three corrections are in [AUTHN-RESULTS.md](AUTHN-RESULTS.md).

## Sources

- S1, feature list, Supported vs Preview (`cimd`, `spiffe`, `client-auth-federated`): https://www.keycloak.org/server/features
- S2, MCP guide 26.8.1 (cimd flag, executor options, URL validation, cache/byte limits): https://www.keycloak.org/securing-apps/mcp-authz-server
- S3, Server Administration Guide, "SPIFFE identity providers": https://www.keycloak.org/docs/latest/server_admin/index.html
- S4, release notes 26.6.0 (federated auth supported; SPIFFE stays preview): https://www.keycloak.org/docs/latest/release_notes/index.html
- S5, `--truststore-paths` semantics: https://www.keycloak.org/server/outgoinghttp
- S6, `SpiffeIdentityProviderConfig.java` / `SpiffeIdentityProviderFactory.java` (`trustDomain`, `bundleEndpoint`, `PROVIDER_ID="spiffe"`, regex): https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/broker/spiffe/SpiffeIdentityProviderConfig.java
- S7, `AbstractClientIdMetadataDocumentExecutorFactory.java` + `…FactoryProviderConfig.java` (option keys, 300/259200/5000 defaults): https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oauth2/cimd/clientpolicy/executor/
- S8, `ClientIdUriSchemeConditionFactory.java` (`client-id-uri` + keys): https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oauth2/cimd/clientpolicy/condition/ClientIdUriSchemeConditionFactory.java
- S9, `OIDCWellKnownProvider.java` (flag iff `Profile.Feature.CIMD`): https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/OIDCWellKnownProvider.java
- S10, Keycloak javadoc `org.keycloak.broker.spiffe` (bundle fields, no `alg`): https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/broker/spiffe/package-summary.html
- S11, `FederatedJWTClientAuthenticator.java` (`federated-jwt`, `jwt.credential.*`): https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/authentication/authenticators/client/FederatedJWTClientAuthenticator.java
- S12, `draft-ietf-oauth-spiffe-client-auth-02` (assertion type, aud rule, `spiffe_id`, bundle rules): https://www.ietf.org/archive/id/draft-ietf-oauth-spiffe-client-auth-02.txt
