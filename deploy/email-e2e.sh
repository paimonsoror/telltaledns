#!/usr/bin/env bash
# REQ: OBS-010 (T9.4) — alert email against a scripted SMTP server: STARTTLS with a private
# certificate (tls_ca), AUTH, the envelope and the message; implicit TLS (smtps://); a wrong
# password is reported, not retried forever; a password is never sent unencrypted (refused by
# configuration). Needs python3 and openssl.
# Usage: deploy/email-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
S=
cleanup() {
  local rc=$?
  for p in $P $S; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  [ -f "$E/node.log" ] && tail -15 "$E/node.log"
  [ -f "$E/smtp.log" ] && tail -15 "$E/smtp.log"
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR

# A private CA (what tls_ca trusts) and the mail server's certificate signed by it.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=e2e-mail-ca \
  -keyout "$E/ca.key" -out "$E/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout "$E/key.pem" -out "$E/req.pem" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$E/ext.cnf"
openssl x509 -req -in "$E/req.pem" -CA "$E/ca.pem" -CAkey "$E/ca.key" -CAcreateserial -days 1 \
  -extfile "$E/ext.cnf" -out "$E/cert.pem" 2>/dev/null

# A minimal SMTP server: STARTTLS on 25587, implicit TLS on 25465. Each accepted message is
# written to mail/<n>.json with its envelope and raw text.
cat > "$E/smtp.py" <<'EOF'
import base64, json, os, socket, ssl, sys, threading
out, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out + "/mail", exist_ok=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
USER, PASS = "alerts@example.com", "app-password-1"
n = [0]
lock = threading.Lock()
def log(*a):
    print(*a, flush=True)
def serve(conn, implicit):
    if implicit:
        conn = ctx.wrap_socket(conn, server_side=True)
    f = conn.makefile("rb")
    def send(line):
        conn.sendall((line + "\r\n").encode())
    def readline():
        raw = f.readline()
        if not raw:
            raise EOFError
        return raw.decode(errors="replace").rstrip("\r\n")
    send("220 localhost ESMTP test")
    tls = implicit
    authed = False
    mail_from, rcpts = None, []
    while True:
        try:
            line = readline()
        except (EOFError, OSError):
            return
        log("C:", "AUTH ..." if line.upper().startswith("AUTH") else line[:60])
        cmd = line.upper()
        if cmd.startswith("EHLO"):
            caps = ["localhost", "8BITMIME", "AUTH PLAIN LOGIN"]
            if not tls:
                caps.insert(1, "STARTTLS")
            for c in caps[:-1]:
                send("250-" + c)
            send("250 " + caps[-1])
        elif cmd == "STARTTLS":
            send("220 go ahead")
            conn = ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            tls = True
        elif cmd.startswith("AUTH PLAIN "):
            if not tls:
                send("538 encryption required"); continue
            _, u, p = base64.b64decode(line.split(" ", 2)[2]).split(b"\0")
            if (u.decode(), p.decode()) == (USER, PASS):
                authed = True; send("235 ok")
            else:
                send("535 5.7.8 bad credentials")
        elif cmd.startswith("MAIL FROM:"):
            if not authed:
                send("530 authentication required"); continue
            mail_from = line[10:].strip("<>"); send("250 ok")
        elif cmd.startswith("RCPT TO:"):
            rcpts.append(line[8:].strip("<>")); send("250 ok")
        elif cmd == "DATA":
            send("354 go")
            lines = []
            while True:
                l = readline()
                if l == ".":
                    break
                lines.append(l[1:] if l.startswith("..") else l)
            with lock:
                n[0] += 1
                with open(f"{out}/mail/{n[0]:03d}.json", "w") as o:
                    json.dump({"from": mail_from, "to": rcpts, "tls": tls, "data": "\r\n".join(lines)}, o)
            send("250 queued")
        elif cmd == "QUIT":
            send("221 bye"); conn.close(); return
        else:
            send("502 unknown")
def listen(port, implicit):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c, implicit), daemon=True).start()
threading.Thread(target=listen, args=(25465, True), daemon=True).start()
listen(25587, False)
EOF
python3 "$E/smtp.py" "$E" "$E/cert.pem" "$E/key.pem" > "$E/smtp.log" 2>&1 & S=$!
for _ in $(seq 50); do
  python3 -c 'import socket; [socket.create_connection(("127.0.0.1", p), 1).close() for p in (25587, 25465)]' 2>/dev/null && break
  sleep 0.1
done
echo -n app-password-1 > "$E/pass"
echo -n wrong-password > "$E/wrong"

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25995"
[api]
listen = "127.0.0.1:26995"
[telemetry.metrics]
listen = "127.0.0.1:27995"
# A list that never downloads: the alert's trigger.
[[list]]
name = "unreachable"
url = "http://127.0.0.1:9/list.txt"
[alerts]
interval_secs = 5
[[alerts.destination]]
name = "mail"
type = "email"
url = "smtp://localhost:25587"
from = "alerts@example.com"
to = ["me@example.com", "you@example.com"]
username = "alerts@example.com"
password_file = "$E/pass"
tls_ca = "$E/ca.pem"
[[alerts.destination]]
name = "mail-tls"
type = "email"
url = "smtps://localhost:25465"
from = "alerts@example.com"
to = ["me@example.com"]
username = "alerts@example.com"
password_file = "$E/pass"
tls_ca = "$E/ca.pem"
[[alerts.destination]]
name = "mail-wrong"
type = "email"
url = "smtp://localhost:25587"
from = "alerts@example.com"
to = ["me@example.com"]
username = "alerts@example.com"
password_file = "$E/wrong"
tls_ca = "$E/ca.pem"
[[alerts.rule]]
name = "Lists failing"
when = "list_failing"
for_secs = 0
to = ["mail", "mail-tls", "mail-wrong"]
# REQ: OBS-010 (T9.5) — a new condition: any disk is fuller than 0.1%.
[[alerts.rule]]
name = "Disk full"
when = "disk_full"
threshold = 0.1
for_secs = 0
to = ["mail"]
EOF

# Configuration check: a password over an unencrypted connection is refused.
sed 's#url = "smtp://localhost:25587"#url = "smtp+insecure://localhost:25587"#' "$E/telltale.toml" > "$E/bad.toml"
if "$B" config check "$E/bad.toml" > "$E/check.txt" 2>&1; then fail "a password over smtp+insecure:// passed the check"; fi
grep -q "never sent unencrypted" "$E/check.txt" || fail "the check didn't explain ($(head -3 "$E/check.txt"))"
echo "ok: config check refuses a password without encryption"

"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 120); do [ "$(ls "$E/mail" 2>/dev/null | wc -l)" -ge 3 ] && break; sleep 0.5; done
[ "$(ls "$E/mail" | wc -l)" -ge 3 ] || fail "three emails (two for the list, one for the disk) didn't arrive"
python3 - "$E/mail" <<'EOF'
import base64, email, json, os, sys
d = sys.argv[1]
msgs = [json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))]
disk = [m for m in msgs if "Subject: [TelltaleDNS] Disk full" in m["data"]]
assert len(disk) == 1 and "data disk is" in base64.b64decode("".join(email.message_from_string(disk[0]["data"]).get_payload().split())).decode(), disk
msgs = [m for m in msgs if m not in disk]
both = [m for m in msgs if len(m["to"]) == 2]
assert both, msgs
m = both[0]
assert m["tls"] and m["from"] == "alerts@example.com" and m["to"] == ["me@example.com", "you@example.com"], m
msg = email.message_from_string(m["data"])
assert msg["Subject"].startswith("[TelltaleDNS] Lists failing: unreachable"), msg["Subject"]
assert msg["To"] == "me@example.com, you@example.com", msg["To"]
body = msg.get_payload(decode=True).decode()
assert "Rule: Lists failing" in body and "Status: firing" in body, body
assert len(msgs) == 2, f"the wrong password must not deliver: {len(msgs)}"
print(f"ok: {len(msgs)} emails (STARTTLS and implicit TLS), subject and body as expected; disk_full fired")
EOF
for _ in $(seq 20); do grep -q 'alert not delivered.*mail-wrong.*535' "$E/node.log" && break; sleep 0.5; done
grep -q 'alert not delivered.*mail-wrong.*535' "$E/node.log" || fail "the wrong password wasn't reported"
echo "ok: a wrong password is reported (535)"
echo "email-e2e: ok"
