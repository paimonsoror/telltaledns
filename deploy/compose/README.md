# TelltaleDNS with Docker Compose (Raspberry Pi / any Linux)

```sh
docker compose up -d
docker compose exec telltale telltale auth setup-token   # then open http://<host>:8053/
```

- `compose.yaml`: host networking (real client IPs and MAC addresses), read-only root
  filesystem, only `NET_BIND_SERVICE`, a healthcheck, and `./data` for lists, the query log, and users.
- `telltale.toml`: a starter config (DNS over TLS to Cloudflare and Quad9, one balanced
  blocklist, a 7-day query log). Edit it and reload with
  `sudo kill -HUP "$(docker inspect -f '{{.State.Pid}}' $(docker compose ps -q telltale))"`
  (not `docker compose kill -s HUP`: the container then doesn't come back after a reboot, see
  [Reload in Docker](../../docs/running.md#reload-in-docker)).
- `TELLTALE_TAG=0.1.0 docker compose up -d` pins a release (default: `latest`, the newest stable release; `edge` follows main).
- `e2e.sh IMAGE` is the CI test of this bundle.

Port 53 busy, running unprivileged, SD-card tips: see "Raspberry Pi and Linux" in
[docs/running.md](../../docs/running.md#raspberry-pi-and-linux). If the container stops at
start with "Address already in use", another program on the host uses port 53: uncomment the
`[[listen]]` example in `telltale.toml` and put in this machine's own address ("Port 53 already
in use" in that section has the details).
