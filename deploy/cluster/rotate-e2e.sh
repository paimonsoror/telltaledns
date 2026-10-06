#!/usr/bin/env bash
# REQ: CLU-001, CLU-005 — T5.4c acceptance (ADR-066): rotate the CA of a running cluster (a
# primary, an eligible replica, a witness) while a client queries the replica.
#   1. `telltale cluster rotate-ca`: every node trusts both CAs, then the new one signs and
#      every node renews from it, then the old CA is retired, with no step before every
#      member is ready;
#   2. afterwards every node trusts only the new CA, every certificate is from it, the eligible
#      replica holds the new key, and no old or next key is left anywhere;
#   3. configuration still replicates (manifests signed with the new key), and a restarted
#      replica reconnects with its new certificate;
#   4. DNS answered every query throughout the rotation.
# Usage: deploy/cluster/rotate-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID= W_PID= LOAD=
cleanup() {
  local rc=$?
  for p in $P_PID $R_PID $W_PID $LOAD; do kill "$p" 2>/dev/null && { wait "$p" 2>/dev/null || true; }; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for n in p r w r2; do [ -f "$E/$n.log" ] && { echo "--- $n log"; grep -iE 'rotat|trust|renew|refused|error|warn' "$E/$n.log" | tail -12; }; done
  [ "${KEEP:-}" = 1 ] && echo "logs kept in $E"
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR

node_config() { # name dns-port api-port metrics-port cluster-port record-value
  cat <<EOF
[node]
name = "$1"
data_dir = "$E/$1"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$2"
[api]
listen = "127.0.0.1:$3"
[telemetry.metrics]
listen = "127.0.0.1:$4"
[cluster]
listen = "127.0.0.1:$5"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[record]]
name = "a.rot.test"
type = "A"
value = "$6"
EOF
}
mkdir -p "$E/p" "$E/r" "$E/w"
node_config p 25411 28111 29111 28551 10.0.0.1 > "$E/p.toml"
node_config r 25412 28112 29112 28552 10.0.0.1 > "$E/r.toml"
cat > "$E/w.toml" <<EOF
[node]
name = "w"
data_dir = "$E/w"
[cluster]
listen = "127.0.0.1:28553"
EOF

cat > "$E/q.py" <<'PY'
import socket, struct, sys, time, random
def query(port, name, timeout=0.5):
    qid = random.randrange(65536)
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, ('127.0.0.1', port)); r, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    return '.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else ''
if sys.argv[1] == 'one':
    a = query(int(sys.argv[2]), sys.argv[3]); print(a if a is not None else 'TIMEOUT')
else:  # load port name stop-file rate: until the stop file exists
    import os
    port, name, stop, rate = int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
    sent = ok = 0
    while not os.path.exists(stop):
        sent += 1; ok += query(port, name, 0.3) is not None; time.sleep(1 / rate)
    print(ok, sent)
PY
# Certificate facts, with the `cryptography` package.
cat > "$E/pki.py" <<'PY'
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
def certs(path):
    return x509.load_pem_x509_certificates(open(path, 'rb').read())
cmd = sys.argv[1]
if cmd == 'count':            # number of CAs in a bundle
    print(len(certs(sys.argv[2])))
elif cmd == 'fp':             # fingerprint of a bundle's first CA
    print(certs(sys.argv[2])[0].fingerprint(hashes.SHA256()).hex())
elif cmd == 'issued-by':      # does CA bundle's first cert sign the node cert?
    ca, node = certs(sys.argv[2])[0], certs(sys.argv[3])[0]
    try:
        node.verify_directly_issued_by(ca); print('yes')
    except Exception:
        print('no')
PY
pki() { python3 "$E/pki.py" "$@"; }
q() { python3 "$E/q.py" one "$@"; }

"$B" cluster init --name rot --advertise https://127.0.0.1:28551 -c "$E/p.toml" >/dev/null
T=$("$B" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25411 a.rot.test)" = 10.0.0.1 ] && break; sleep 0.1; done
join() {
  for _ in $(seq 40); do "$B" cluster join "$T" "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "couldn't join: $*"
}
join --site r --eligible --advertise https://127.0.0.1:28552 -c "$E/r.toml"
join --site w --witness --advertise https://127.0.0.1:28553 -c "$E/w.toml"
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!
"$B" cluster witness -c "$E/w.toml" > "$E/w.log" 2>&1 & W_PID=$!
for _ in $(seq 60); do [ -f "$E/r/cluster/ca.key" ] && break; sleep 0.25; done
[ -f "$E/r/cluster/ca.key" ] || fail "the eligible replica never received the cluster key"
old=$(pki fp "$E/p/cluster/ca.crt")
old_key=$(sha256sum < "$E/p/cluster/ca.key")
echo "== cluster up (CA ${old:0:16})"

echo "== 1. rotate the CA under load"
python3 "$E/q.py" load 25412 a.rot.test "$E/stop" 40 > "$E/load.txt" & LOAD=$!
"$B" cluster rotate-ca -c "$E/p.toml"
for i in $(seq 120); do
  [ -f "$E/p/cluster/rotation.json" ] || break
  [ $((i % 10)) = 0 ] && "$B" cluster rotate-ca --status -c "$E/p.toml" | tail -1
  sleep 2
done
[ ! -f "$E/p/cluster/rotation.json" ] || fail "the rotation didn't finish in 4 minutes: $("$B" cluster rotate-ca --status -c "$E/p.toml")"
new=$(pki fp "$E/p/cluster/ca.crt")
[ "$new" != "$old" ] || fail "the CA didn't change"
echo "ok (new CA ${new:0:16})"

echo "== 2. one CA everywhere, every certificate from it"
# Replicas adopt the final bundle from the next manifest.
# A replica adopts the bundle a moment before it removes its rotation files: wait for both.
settled() {
  local n f
  for n in r w; do
    [ "$(pki count "$E/$n/cluster/ca.crt")" = 1 ] || return 1
    for f in ca-old.key ca-next.key ca-pending.key rotation.json; do
      [ ! -e "$E/$n/cluster/$f" ] || return 1
    done
  done
}
for _ in $(seq 60); do
  settled && break
  sleep 1
done
for n in p r w; do
  [ "$(pki count "$E/$n/cluster/ca.crt")" = 1 ] || fail "$n still trusts $(pki count "$E/$n/cluster/ca.crt") CAs"
  [ "$(pki fp "$E/$n/cluster/ca.crt")" = "$new" ] || fail "$n trusts another CA"
  [ "$(pki issued-by "$E/$n/cluster/ca.crt" "$E/$n/cluster/node.crt")" = yes ] || fail "$n's certificate isn't from the new CA"
  for f in ca-old.key ca-next.key ca-pending.key rotation.json; do
    [ ! -e "$E/$n/cluster/$f" ] || fail "$n kept $f"
  done
done
# The primary signs with a new key (manifests verify against the new CA in step 3), and the
# eligible replica holds the same one, so it can take over.
[ "$(sha256sum < "$E/p/cluster/ca.key")" != "$old_key" ] || fail "the primary's cluster key didn't change"
cmp -s "$E/p/cluster/ca.key" "$E/r/cluster/ca.key" || fail "the eligible replica doesn't hold the new cluster key"
[ ! -e "$E/w/cluster/ca.key" ] || fail "the witness holds a cluster key"
grep -q 'CA rotation finished' "$E/p.log" || fail "the primary didn't log the end of the rotation"
echo ok

# The load covers the rotation; step 3 restarts the replica on purpose.
echo "== DNS throughout the rotation"
touch "$E/stop"; wait "$LOAD"; LOAD=
read -r ok sent < "$E/load.txt"
[ "$ok" = "$sent" ] || fail "DNS missed answers during the rotation: $ok of $sent"
echo "ok ($ok of $sent queries answered)"

echo "== 3. replication and reconnection with the new CA"
sed -i 's/value = "10.0.0.1"/value = "10.0.0.2"/' "$E/p.toml"
kill -HUP "$P_PID"
for _ in $(seq 60); do [ "$(q 25412 a.rot.test)" = 10.0.0.2 ] && break; sleep 0.25; done
[ "$(q 25412 a.rot.test)" = 10.0.0.2 ] || fail "a change didn't reach the replica after the rotation"
kill "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=
"$B" run -c "$E/r.toml" > "$E/r2.log" 2>&1 & R_PID=$!
sed -i 's/value = "10.0.0.2"/value = "10.0.0.3"/' "$E/p.toml"
kill -HUP "$P_PID"
for _ in $(seq 120); do [ "$(q 25412 a.rot.test)" = 10.0.0.3 ] && break; sleep 0.25; done
[ "$(q 25412 a.rot.test)" = 10.0.0.3 ] || fail "the restarted replica didn't reconnect and sync"
echo ok

echo PASS
