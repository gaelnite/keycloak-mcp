#!/usr/bin/env bash
# End-to-end verification for the Keycloak MCP reference.
# Every check is read-only except the token requests. Exits non-zero on failure.
set -uo pipefail
KC="${KC:-https://localhost:8443}"
REALM="${REALM:-lab}"
MCP="${MCP:-http://127.0.0.1:8800}"
CADIR="${CADIR:-$HOME/.config/keycloak-mcp/certs}"
LAB="${LAB:-$(cd "$(dirname "$0")/.." && pwd)}"
CURL="curl -s --cacert $CADIR/ca.crt"
pass=0; fail=0
ok(){ echo "PASS  $1"; pass=$((pass+1)); }
no(){ echo "FAIL  $1 ${2:-}"; fail=$((fail+1)); }

# 1. Discovery advertises CIMD
flag=$($CURL "$KC/realms/$REALM/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('client_id_metadata_document_supported'))")
[ "$flag" = "True" ] && ok "CIMD advertised in realm discovery" || no "CIMD advertised" "(got $flag)"

# 2. Health + metrics on the management interface
[ "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:9000/health/ready)" = 200 ] && ok "keycloak health" || no "keycloak health"
[ "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:9000/metrics)" = 200 ] && ok "native metrics" || no "native metrics"

# 3. CIMD document and SPIFFE bundle are served with the lab CA
$CURL -o /tmp/v-cimd.json -w "%{http_code}" https://localhost:9444/client-metadata.json | grep -q 200 && ok "CIMD document served" || no "CIMD document"
$CURL -o /tmp/v-bundle.json -w "%{http_code}" https://localhost:9444/bundle.json | grep -q 200 && ok "SPIFFE bundle served" || no "SPIFFE bundle"

# 4. Positive SVID token, then assert claims
tok_resp=$($CURL -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d "client_id=https://localhost:9444/client-metadata.json" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe" \
  -d "client_assertion=$(cat "$LAB/cimd/svid.jwt")")
printf '%s' "$tok_resp" > /tmp/v-tok.json
python3 - "$KC" <<'PY' && ok "SVID -> access token with aud/azp/scope" || no "SVID token"
import base64,json,sys
d=json.load(open("/tmp/v-tok.json"))
if "access_token" not in d: print(" ", d); raise SystemExit(1)
p=d["access_token"].split(".")[1]; p+="="*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p))
need={"aud":"https://localhost:8800/mcp","azp":"https://localhost:9444/client-metadata.json"}
for k,v in need.items():
    got=c.get(k); got=got[0] if isinstance(got,list) and got else got
    if got!=v: print(f"  {k}={got!r} expected {v!r}"); raise SystemExit(1)
if "keycloak.realms.read" not in (c.get("scope") or ""): print("  missing scope"); raise SystemExit(1)
open("/tmp/v-token","w").write(d["access_token"])
PY
TOKEN=$(cat /tmp/v-token 2>/dev/null)

# 5. Negative: a SVID minted for the wrong audience must be rejected
python3 "$LAB/scripts/mint-svid.py" mint --trust-domain spiffe://lab.local \
  --subject spiffe://lab.local/workload/mcp-client --audience https://wrong.example >/dev/null 2>&1
code=$($CURL -o /tmp/v-neg.json -w "%{http_code}" -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d "client_id=https://localhost:9444/client-metadata.json" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe" \
  -d "client_assertion=$(cat "$LAB/cimd/svid.jwt")")
[ "$code" = 400 ] && ok "wrong-audience SVID rejected (400)" || no "wrong-audience SVID" "(got $code)"
# restore a good SVID
python3 "$LAB/scripts/mint-svid.py" mint --trust-domain spiffe://lab.local \
  --subject spiffe://lab.local/workload/mcp-client --audience "$KC/realms/$REALM" >/dev/null 2>&1

# 6. MCP surface
[ "$(curl -s -o /dev/null -w '%{http_code}' "$MCP/healthz")" = 200 ] && ok "MCP healthz" || no "MCP healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MCP/mcp" -H 'Content-Type: application/json' -d '{}')" = 401 ] && ok "MCP rejects unauthenticated" || no "MCP unauthenticated 401"

if [ -n "${TOKEN:-}" ]; then
  H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
  curl -s -D /tmp/v-h -o /dev/null "${H[@]}" -X POST "$MCP/mcp" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}'
  SID=$(grep -i '^mcp-session-id:' /tmp/v-h | tr -d '\r' | awk '{print $2}')
  if [ -n "$SID" ]; then
    ok "MCP initialize"
    out=$(curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" -X POST "$MCP/mcp" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_realms","arguments":{}}}')
    echo "$out" | grep -q 'displayName' && ok "tools/call list_realms reached Keycloak" || no "tools/call list_realms" "(payload in MCP audit/log)"
    out=$(curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" -X POST "$MCP/mcp" \
      -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_extension_inventory","arguments":{}}}')
    echo "$out" | grep -q 'magic-link' && ok "extension inventory reports magic-link" || no "extension inventory" "(payload in MCP audit/log)"
  else
    no "MCP initialize" "(no session id)"
  fi
fi

echo "----------------------------------------"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
