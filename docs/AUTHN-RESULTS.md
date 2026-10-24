# AuthN results, verified

Live results from the deployed lab, 2026-10-23, Keycloak **26.8.1**, OpenJDK/Quarkus build, realm `lab`.
This file is the evidence behind `docs/AUTHN.md`; where the guide was uncertain, this resolves it.
All values were observed from the running server, not inferred.

## Setup under test

| Piece | Value |
|---|---|
| Keycloak | `https://localhost:8443`, realm `lab`, features `cimd,spiffe` (baked, `--optimized`) |
| Lab CA | `~/.config/keycloak-mcp/certs/ca.crt`, trusted by Keycloak via `KC_TRUSTSTORE_PATHS` |
| CIMD document | `https://localhost:9444/client-metadata.json` (served by `cimd/serve.py`, CA-signed) |
| SPIFFE bundle | `https://localhost:9444/bundle.json` (minted by `scripts/mint-svid.py`) |
| Trust domain | `spiffe://lab.local`, subject `spiffe://lab.local/workload/mcp-client` |
| Client | `clientId` = the CIMD URL, `clientAuthenticatorType=federated-jwt`, service account |
| CIMD policy | profile `cimd-profile` (executor `client-id-metadata-document`), policy `cimd-policy` (condition `client-id-uri`) |

## Verified flows

| # | Probe | Result |
|---|---|---|
| A1 | Realm discovery advertises CIMD | `client_id_metadata_document_supported: true`; `none` present in `token_endpoint_auth_methods_supported` |
| A2 | Keycloak fetches the CIMD document | `serve.py` logs `GET /client-metadata.json 200` during the token request |
| A3 | Keycloak fetches the SPIFFE bundle | `serve.py` logs `GET /bundle.json 200` (twice: registration + token) |
| A4 | **Positive: SVID → access token** | **HTTP 200**; `azp` = `https://localhost:9444/client-metadata.json`; `iss` = `https://localhost:8443/realms/lab` |
| A5 | Audience mapper | `aud` contains `https://localhost:8800/mcp` (the MCP resource) plus `account` |
| A6 | Scope claim | `scope` includes `keycloak.realms.read`, `keycloak.users.read`, … once the client scopes are assigned |
| A7 | Realm role | `realm_access.roles` includes `mcp-admin` (assigned to the service account) |
| A8 | Wrong audience in SVID | **400 `invalid_client` "Invalid token audience"** |
| A9 | Wrong subject in SVID | **401 `invalid_client`** |
| A10 | Expired SVID (`exp < now`) | **400 `invalid_client` "Token is not active"** |
| A11 | Wrong assertion type (`jwt-bearer`) | **401 `invalid_client`** |
| A12 | **Dynamic CIMD client creation** (URL not pre-registered) | authorization request fetched `dynamic.json` and **created a client**: `clientId` = URL, `publicClient=true`, `clientAuthenticatorType=none`, redirect URIs from the document |
| A13 | Client policies API shape | `PUT /client-policies/{profiles,policies}` takes `{"profiles":[…]}` / `{"policies":[…]}`; `POST` returns 405 |

## Corrections to the guide (important)

1. **Executor option encoding is typed.** `cimd-allow-http-scheme` is a JSON **boolean**, `cimd-allow-permitted-domains`
   and `cimd-required-properties` are **arrays of strings**, cache/byte limits are numbers. Sending `["false"]` for
   the boolean yields HTTP 500 "Cannot parse the JSON" with a Jackson trace naming
   `ClientIdMetadataDocumentExecutor$Configuration["cimd-allow-http-scheme"]`. The working body is in
   `terraform/` plus `realm/cimd-*.json` (see repo) and reproduced below.
2. **Trusted domains apply to URLs inside the document, not only `client_id`.** A document at `localhost` with a
   `redirect_uri` on `127.0.0.1` failed with `not trusted domain: host = 127.0.0.1` until `127.0.0.1` was added.
3. **CIMD and `federated-jwt` do compose for a pre-registered client.** The token flow in A4 used a client whose
   `clientId` is the CIMD URL and whose authenticator is `federated-jwt`; Keycloak fetched the document *and*
   validated the SVID. The earlier open question in `03 §9.1` is answered for this shape.
4. **A dynamically created CIMD client is public (`none`).** It cannot use an SVID assertion; it is a PKCE client.
   So: CIMD-created clients ≠ SVID clients unless a federation field is added to the document (not standardised).
5. **`only-allow-confidential-client` must stay `false` for MCP.** Real MCP clients (Claude, Cursor, VS Code)
   publish `token_endpoint_auth_method: none`; a confidential-only CIMD profile rejects them before consent.
6. **Keycloak hard-rejects a query string in `client_id`** (draft says SHOULD NOT) and requires the 5 KB document
   cap, https, a path, no fragment/userinfo/dot-segments.

## Reproducing

```bash
cd ~/Dev/keycloak-mcp
./scripts/verify.sh            # automates A1–A11 and the MCP chain
# manual token request:
SVID=$(cat cimd/svid.jwt)
curl -sk -X POST https://localhost:8443/realms/lab/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d 'client_id=https://localhost:9444/client-metadata.json' \
  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe' \
  -d "client_assertion=$SVID" | jq -r .access_token | cut -d. -f2 | base64 -d 2>/dev/null
```

## Admin API snippets that worked

```bash
# profiles (typed options; note the wrapper object)
curl -sk -X PUT -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  "$KC/admin/realms/lab/client-policies/profiles" -d '{"profiles":[{"name":"cimd-profile",
  "executors":[{"executor":"client-id-metadata-document","configuration":{
    "cimd-allow-http-scheme":false,"cimd-allow-permitted-domains":["localhost","127.0.0.1"],
    "only-allow-confidential-client":false,"accept-public-client-with-confidential-client-only-grant":true,
    "min-cache-time":300,"max-cache-time":259200,"upper-limit-metadata-bytes":5000}}]}]}'

# SPIFFE identity provider
curl -sk -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  "$KC/admin/realms/lab/identity-provider/instances" -d '{"alias":"spiffe-lab","providerId":"spiffe",
  "enabled":true,"config":{"trustDomain":"spiffe://lab.local",
  "bundleEndpoint":"https://localhost:9444/bundle.json","allowedClockSkew":"30"}}'
```

## Still open / not verified

- Whether a CIMD document can carry a **federated-jwt** declaration. No standard field exists; a dynamically
  created client came out `none`, so today it requires pre-registration.
- Refresh-token and offline-access behaviour for SVID clients (not exercised; lab tokens are 300 s).
- SPIRE itself. The lab mints SVIDs with a script; a real deployment would replace `scripts/mint-svid.py` with
  SPIRE and the same bundle endpoint, with `trustDomain`/`bundleEndpoint` pointing at it.
