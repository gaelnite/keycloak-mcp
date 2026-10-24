#!/usr/bin/env bash
# End-to-end AuthN demo for the Keycloak 26.8.1 lab:
# SPIFFE JWT-SVID client authentication + Client ID Metadata Document (CIMD).
#
# Everything here is a plain curl against Keycloak. Nothing is mocked; the
# only synthetic part is the SVID itself, minted by scripts/mint-svid.py.
#
# Prerequisites (see docs/AUTHN.md):
#   1. Keycloak started with:  --features=cimd,spiffe
#      and, on a private CA:   --truststore-paths=/etc/ssl/lab/lab-ca.pem
#   2. cimd/serve.py running on https://cimd.lab.local:8444
#   3. The client registered (scripts/03 in the guide) OR CIMD accepted.
#
# Env overrides:
#   KC=https://kc.lab.local:8443   REALM=lab
#   CLIENT_ID=https://cimd.lab.local:8444/client-metadata.json
#   SPIFFE_ID=spiffe://lab.local/workload/mcp-client
#   SCOPE=mcp:tools   CIMD_URL=https://cimd.lab.local:8444/client-metadata.json
#
# Exit status: 0 only if every positive case passed and every negative case
# was rejected. This is intended to be the acceptance test, not a demo script.

set -uo pipefail

KC="${KC:-https://kc.lab.local:8443}"
REALM="${REALM:-lab}"
CLIENT_ID="${CLIENT_ID:-https://cimd.lab.local:8444/client-metadata.json}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://lab.local/workload/mcp-client}"
CIMD_URL="${CIMD_URL:-https://cimd.lab.local:8444/client-metadata.json}"
SCOPE="${SCOPE:-}"
TOKEN_ENDPOINT="${KC}/realms/${REALM}/protocol/openid-connect/token"
DISCOVERY="${KC}/realms/${REALM}/.well-known/openid-configuration"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINT="${HERE}/mint-svid.py"
FAIL=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  SKIP  %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 2; }; }
need curl
need python3

# ---------------------------------------------------------------------------
say "1. Feature flags visible in realm discovery"
disc_body="$(curl -sS -m 10 "$DISCOVERY" 2>&1)" || disc_body=""
cimd_flag="$(printf '%s' "$disc_body" | python3 -c \
  'import json,sys;
try: print(json.load(sys.stdin).get("client_id_metadata_document_supported"))
except Exception: print("PARSE_ERROR")' 2>/dev/null)"
echo "  client_id_metadata_document_supported = ${cimd_flag}"
case "$cimd_flag" in
  True) ok "CIMD is enabled (feature cimd)" ;;
  None|PARSE_ERROR) bad "flag absent -- is --features=cimd set in this realm?" ;;
  *) bad "unexpected flag value: $cimd_flag" ;;
esac

# ---------------------------------------------------------------------------
say "2. Keycloak can be talked to at all"
code="$(curl -sS -o /dev/null -w '%{http_code}' -m 10 "$DISCOVERY" 2>/dev/null)"
[ "$code" = "200" ] && ok "discovery 200" || bad "discovery returned $code"

# ---------------------------------------------------------------------------
say "3. The CIMD document is served and self-consistent"
doc="$(curl -sS -m 10 "$CIMD_URL" 2>&1)" || doc=""
printf '%s' "$doc" | python3 -c '
import json,sys
url=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception as e:
    print(f"  FAIL  document is not JSON: {e}"); sys.exit(1)
print(f"  client_id in doc : {d.get(\"client_id\")}")
print(f"  fetched from     : {url}")
print(f"  spiffe_id        : {d.get(\"spiffe_id\")}")
print(f"  bundle endpoint  : {d.get(\"spiffe_bundle_endpoint\")}")
sys.exit(0 if d.get("client_id")==url else 1)
' "$CIMD_URL" && ok "client_id matches the URL exactly" \
                 || bad "client_id does not match the URL (CIMD -02 §4)"

# ---------------------------------------------------------------------------
say "4. The SPIFFE bundle endpoint is served"
bundle_url="$(printf '%s' "$doc" | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("spiffe_bundle_endpoint",""))' 2>/dev/null)"
if [ -n "$bundle_url" ]; then
  bcode="$(curl -sS -o /tmp/svid-bundle.json -w '%{http_code}' -m 10 "$bundle_url" 2>/dev/null)"
  [ "$bcode" = "200" ] && ok "bundle 200 ($bundle_url)" || bad "bundle returned $bcode"
  python3 -c '
import json
d=json.load(open("/tmp/svid-bundle.json"))
keys=[k for k in d.get("keys",[]) if k.get("use")=="jwt-svid"]
print(f"  jwt-svid keys: {len(keys)}  spiffe_sequence={d.get(\"spiffe_sequence\")}")
raise SystemExit(0 if keys else 1)
' && ok "bundle contains use=jwt-svid keys" || bad "bundle has no jwt-svid keys"
else
  skip "no spiffe_bundle_endpoint in the document"
fi

# ---------------------------------------------------------------------------
say "5. Positive: SVID with correct aud + sub is accepted"
AUD="${KC}/realms/${REALM}"
svid="$("$MINT" mint --trust-domain spiffe://lab.local --subject "$SPIFFE_ID" \
        --audience "$AUD" 2>/dev/null)"
[ -n "$svid" ] && ok "minted SVID for $SPIFFE_ID" || bad "mint-svid.py produced nothing"

post_token() { # $1=svid, $2=assertion type (optional)
  local atype="${2:-urn:ietf:params:oauth:client-assertion-type:jwt-spiffe}"
  local args=(--data-urlencode "grant_type=client_credentials"
              --data-urlencode "client_id=${CLIENT_ID}"
              --data-urlencode "client_assertion_type=${atype}"
              --data-urlencode "client_assertion=$1")
  [ -n "$SCOPE" ] && args+=(--data-urlencode "scope=$SCOPE")
  curl -sS -o /tmp/tok-body.json -w '%{http_code}' -m 15 -X POST "$TOKEN_ENDPOINT" \
    -H 'Content-Type: application/x-www-form-urlencoded' "${args[@]}" 2>/dev/null
}

code="$(post_token "$svid")"
if [ "$code" = "200" ]; then
  ok "token endpoint 200"
  python3 - "$AUD" <<'PY'
import base64, json, sys
d = json.load(open("/tmp/tok-body.json"))
tok = d.get("access_token", "")
def pad(s): return s + "=" * (-len(s) % 4)
claims = json.loads(base64.urlsafe_b64decode(pad(tok.split(".")[1]))) if tok.count(".") == 2 else {}
print(f"  token_type      : {d.get('token_type')}")
print(f"  client_id claim : {claims.get('client_id')}")
print(f"  azp             : {claims.get('azp')}")
print(f"  sub             : {claims.get('sub')}")
print(f"  aud             : {claims.get('aud')}")
print(f"  exp-iat         : {(claims.get('exp') or 0) - (claims.get('iat') or 0)}s")
expected_aud = sys.argv[1]
aud = claims.get("aud")
aud_ok = expected_aud in (aud if isinstance(aud, list) else [aud])
print(f"  aud contains AS : {aud_ok}")
raise SystemExit(0 if aud_ok else 1)
PY
  [ $? -eq 0 ] && ok "access token carries azp/client_id and an aud bound to this AS" \
                || bad "access token aud does not reference the AS"
else
  bad "token endpoint returned $code"
  echo "  body: $(head -c 400 /tmp/tok-body.json 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
say "6. Negative cases (each MUST be rejected)"
neg() { # $1=label, $2=svid, $3=optional assertion type
  local label="$1" s="$2" at="${3:-}"
  local c
  if [ -n "$at" ]; then c="$(post_token "$s" "$at")"; else c="$(post_token "$s")"; fi
  local body; body="$(head -c 300 /tmp/tok-body.json 2>/dev/null)"
  if [ "$c" = "200" ]; then
    bad "$label -> ACCEPTED (200). Security bug or misconfiguration."
  else
    ok "$label -> $c $body"
  fi
}

wrong_aud="$("$MINT" mint --trust-domain spiffe://lab.local --subject "$SPIFFE_ID" \
             --audience https://attacker.example 2>/dev/null)"
neg "wrong aud" "$wrong_aud"

wrong_sub="$("$MINT" mint --trust-domain spiffe://lab.local \
             --subject spiffe://lab.local/workload/somebody-else --audience "$AUD" 2>/dev/null)"
neg "wrong spiffe_id / sub" "$wrong_sub"

expired="$("$MINT" mint --trust-domain spiffe://lab.local --subject "$SPIFFE_ID" \
           --audience "$AUD" --exp-offset -120 2>/dev/null)"
neg "expired SVID" "$expired"

neg "wrong client_assertion_type" "$svid" \
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# ---------------------------------------------------------------------------
say "7. Optional: CIMD-created client (only if the CIMD policy is active)"
# The client_id below is a URL, so Keycloak must fetch the document before it
# can even identify the client. A 401 with an invalid_client-style error here is
# EXPECTED until the CIMD client policy is configured (step 3 of the guide).
c="$(curl -sS -o /tmp/authz-body.txt -w '%{http_code}' -m 15 \
  "$KC/realms/$REALM/protocol/openid-connect/auth" \
  --get --data-urlencode "client_id=$CIMD_URL" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "redirect_uri=http://127.0.0.1:8765/callback" \
  --data-urlencode "state=lab" --data-urlencode "code_challenge=abc" \
  --data-urlencode "code_challenge_method=S256" 2>/dev/null)"
echo "  authorize -> HTTP $c (a 302/200 means the CIMD document was fetched)"

# ---------------------------------------------------------------------------
say "Result"
if [ "$FAIL" -eq 0 ]; then
  echo "  ALL CHECKS PASSED"
  exit 0
fi
echo "  $FAIL CHECK(S) FAILED"
exit 1
