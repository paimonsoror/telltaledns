#!/usr/bin/env bash
# REQ: API-007 — T6.3 acceptance against real Pi-hole exports (needs Docker and internet).
# For each of Pi-hole v6 and v5 (official images, pinned):
#   1. configure groups, clients, adlists, allow/deny domains (exact and regex), local DNS and
#      CNAME records, upstreams, conditional forwarding, DHCP reservations, blocking mode;
#   2. export a Teleporter archive with Pi-hole's own tool;
#   3. `telltale import pihole` it; the output must load and carry each of those over;
#   4. run TelltaleDNS on it and check the answers: local names, a CNAME's TTL, an exact
#      deny and a regex deny (with ;querytype) blocked with EDE 15 as NXDOMAIN.
# Usage: deploy/pihole-import-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
V6_IMAGE=pihole/pihole:2026.09.0
V5_IMAGE=pihole/pihole:2024.07.0
E=$(mktemp -d)
P=
cleanup() {
  [ -n "$P" ] && kill "$P" 2>/dev/null && wait "$P" 2>/dev/null
  docker rm -f tt-ph6 tt-ph5 >/dev/null 2>&1 || true
  rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for f in "$E"/*.log "$E"/*.err; do [ -f "$f" ] && { echo "--- $(basename "$f")"; tail -20 "$f"; }; done
  exit 1
}
command -v dig >/dev/null || { echo "needs dig"; exit 2; }
command -v docker >/dev/null || { echo "needs docker"; exit 2; }

# The same group setup for both versions, through Pi-hole's documented gravity.db schema.
SQL="
INSERT INTO \"group\"(name,enabled,description) VALUES('Kids',1,'children''s devices'),('IoT',0,'switched off');
INSERT INTO adlist(address,enabled,comment) VALUES('https://lists.example/kids.txt',1,'kids list'),('https://lists.example/off.txt',0,'disabled list');
DELETE FROM adlist_by_group WHERE adlist_id=(SELECT id FROM adlist WHERE address='https://lists.example/kids.txt');
INSERT INTO adlist_by_group(adlist_id,group_id) SELECT id,(SELECT id FROM \"group\" WHERE name='Kids') FROM adlist WHERE address='https://lists.example/kids.txt';
INSERT INTO domainlist(type,domain,enabled,comment) VALUES
 (0,'allowed.example',1,'exact allow'),
 (1,'denied.example',1,'exact deny'),
 (2,'(^|\\.)good\\.example\$',1,'regex allow'),
 (3,'^ad[0-9]+\\.example\$;querytype=A',1,'regex deny'),
 (1,'disabled.example',0,'off'),
 (1,'kidsonly.example',1,'kids deny');
DELETE FROM domainlist_by_group WHERE domainlist_id=(SELECT id FROM domainlist WHERE domain='kidsonly.example');
INSERT INTO domainlist_by_group(domainlist_id,group_id) SELECT id,(SELECT id FROM \"group\" WHERE name='Kids') FROM domainlist WHERE domain='kidsonly.example';
INSERT INTO client(ip,comment) VALUES('192.168.1.50','Kids tablet'),('10.0.5.0/24','guest net'),('AA:BB:CC:DD:EE:02','TV'),('laptop.lan','by name');
DELETE FROM client_by_group WHERE client_id=(SELECT id FROM client WHERE ip='192.168.1.50');
INSERT INTO client_by_group(client_id,group_id) SELECT id,(SELECT id FROM \"group\" WHERE name='Kids') FROM client WHERE ip='192.168.1.50';
"

wait_for() { # container, command that succeeds when ready
  for _ in $(seq 1 120); do docker exec "$1" sh -c "$2" >/dev/null 2>&1 && return 0; sleep 2; done
  docker logs --tail 30 "$1" > "$E/$1.log" 2>&1
  fail "$1 didn't become ready"
}

echo "== Pi-hole v6 ($V6_IMAGE)"
docker run -d --name tt-ph6 -e TZ=UTC -e FTLCONF_webserver_api_password=e2e "$V6_IMAGE" >/dev/null
# Probe only once gravity.db exists: sqlite3 would create an empty one and break Pi-hole.
wait_for tt-ph6 "test -s /etc/pihole/gravity.db && pihole-FTL sqlite3 /etc/pihole/gravity.db 'select count(*) from adlist_by_group'"
sleep 3
# Back-to-back --config writes can be lost while FTL rewrites pihole.toml: set, read back,
# retry. $3 is a string the value must show.
c6() {
  for _ in $(seq 10); do
    docker exec tt-ph6 pihole-FTL --config "$1" "$2" >/dev/null 2>&1 || true
    sleep 1
    docker exec tt-ph6 pihole-FTL --config "$1" 2>/dev/null | grep -qF -- "$3" && return 0
  done
  fail "Pi-hole v6 didn't keep $1"
}
c6 dns.upstreams '["9.9.9.9", "127.0.0.1#5335"]' 127.0.0.1#5335
c6 dns.hosts '["192.168.1.10 nas.lan nas", "fd00::10 nas.lan"]' fd00::10
c6 dns.cnameRecords '["media.lan,nas.lan", "tv.lan,nas.lan,300"]' tv.lan
c6 dns.revServers '["true,192.168.1.0/24,192.168.1.1,lan"]' 192.168.1.0/24
c6 dns.blocking.mode NX NX
c6 dns.rateLimit.count 500 500
c6 dhcp.hosts '["aa:bb:cc:dd:ee:01,192.168.1.50,kids-tablet"]' kids-tablet
c6 misc.privacylevel 1 1
docker exec -i tt-ph6 pihole-FTL sqlite3 /etc/pihole/gravity.db <<< "$SQL"
docker exec tt-ph6 sh -c 'cd /tmp && rm -f *teleporter*.zip && pihole-FTL --teleporter >/dev/null'
f=$(docker exec tt-ph6 sh -c 'ls /tmp | grep -i "teleporter.*zip" | head -1')
[ -n "$f" ] || fail "v6 produced no Teleporter archive"
docker cp "tt-ph6:/tmp/$f" "$E/v6.zip" >/dev/null
docker rm -f tt-ph6 >/dev/null

echo "== Pi-hole v5 ($V5_IMAGE)"
docker run -d --name tt-ph5 -e TZ=UTC -e WEBPASSWORD=e2e "$V5_IMAGE" >/dev/null
wait_for tt-ph5 "test -s /etc/pihole/gravity.db && sqlite3 /etc/pihole/gravity.db 'select count(*) from adlist_by_group' && pgrep pihole-FTL"
sleep 5
docker exec tt-ph5 sh -c 'sed -i "/^PIHOLE_DNS_/d;/^REV_SERVER/d" /etc/pihole/setupVars.conf
printf "PIHOLE_DNS_1=9.9.9.9\nPIHOLE_DNS_2=127.0.0.1#5335\nREV_SERVER=true\nREV_SERVER_CIDR=192.168.1.0/24\nREV_SERVER_TARGET=192.168.1.1\nREV_SERVER_DOMAIN=lan\n" >> /etc/pihole/setupVars.conf
printf "192.168.1.10 nas.lan\nfd00::10 nas.lan\n" > /etc/pihole/custom.list
printf "cname=media.lan,nas.lan\ncname=tv.lan,nas.lan,300\n" > /etc/dnsmasq.d/05-pihole-custom-cname.conf
printf "dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.50,kids-tablet\n" > /etc/dnsmasq.d/04-pihole-static-dhcp.conf
printf "RATE_LIMIT=500/60\nBLOCKINGMODE=NXDOMAIN\nPRIVACYLEVEL=1\n" >> /etc/pihole/pihole-FTL.conf'
docker exec -i tt-ph5 sqlite3 /etc/pihole/gravity.db <<< "$SQL"
# The web UI's Teleporter export, run directly.
docker exec tt-ph5 sh -c 'php /var/www/html/admin/scripts/pi-hole/php/teleporter.php > /tmp/tp.tar.gz'
docker cp tt-ph5:/tmp/tp.tar.gz "$E/v5.tar.gz" >/dev/null
docker rm -f tt-ph5 >/dev/null

port=25961
for v in v6.zip v5.tar.gz; do
  echo "== import $v"
  "$B" import pihole "$E/$v" -o "$E/$v.toml" 2> "$E/$v.err" || fail "import of $v failed"
  cat "$E/$v.err"
  t="$E/$v.toml"
  for want in 'url = "udp://9.9.9.9:53"' 'url = "udp://192.168.1.1:53"' '"1.168.192.in-addr.arpa"' \
      'name = "Kids"' 'name = "IoT"' 'match = ["192.168.1.50", "aa:bb:cc:dd:ee:01"]' \
      'groups = ["Kids"]' 'url = "https://lists.example/kids.txt"' 'block_mode = "nxdomain"' \
      'queries = 500' 'rules = ["kidsonly.example"]' 'match = ["10.0.5.0/24"]'; do
    grep -qF "$want" "$t" || fail "$v: the import lacks $want"
  done
  grep -q 'laptop.lan' "$E/$v.err" || fail "$v: the host-name client isn't reported"
  grep -q 'DHCP\|privacylevel\|PRIVACYLEVEL' "$E/$v.err" || fail "$v: unmapped settings aren't reported"

  # Serve it.
  port=$((port + 1))
  cat > "$E/run.toml" <<EOF
[node]
data_dir = "$E/data-$port"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$port"
[api]
listen = "127.0.0.1:$((port + 1000))"
[telemetry.metrics]
listen = "127.0.0.1:$((port + 2000))"
# The test's lists.example URLs don't exist: don't wait through retries.
[filter]
fetch_retries = 0
EOF
  "$B" run -c "$E/run.toml" -c "$t" > "$E/serve-$v.log" 2>&1 & P=$!
  d() { dig +time=2 +tries=2 -p "$port" @127.0.0.1 "$@"; }
  for _ in $(seq 100); do d +short nas.lan A 2>/dev/null | grep -q 192.168.1.10 && break; sleep 0.2; done
  [ "$(d +short nas.lan A)" = 192.168.1.10 ] || fail "$v: nas.lan doesn't answer 192.168.1.10"
  [ "$(d +short nas.lan AAAA)" = fd00::10 ] || fail "$v: nas.lan AAAA"
  d tv.lan A | grep -q 'tv.lan.*300.*CNAME.*nas.lan' || fail "$v: tv.lan isn't a CNAME with TTL 300"
  # Inline lists compile in the background.
  for _ in $(seq 60); do d denied.example A | grep -q 'EDE: 15' && break; sleep 0.5; done
  out=$(d denied.example A)
  echo "$out" | grep -q 'EDE: 15' || fail "$v: denied.example isn't blocked"
  echo "$out" | grep -q 'status: NXDOMAIN' || fail "$v: blocking mode isn't NXDOMAIN"
  d ad7.example A | grep -q 'EDE: 15' || fail "$v: the regex deny doesn't block ad7.example A"
  d ad7.example AAAA | grep -q 'EDE: 15' && fail "$v: ;querytype=A blocked AAAA too"
  d kidsonly.example A | grep -q 'EDE: 15' && fail "$v: a Kids-only entry blocked the default group"
  kill "$P"; wait "$P" 2>/dev/null || true; P=
  echo "PASS $v"
done
echo PASS
