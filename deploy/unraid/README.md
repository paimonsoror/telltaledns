# TelltaleDNS on Unraid

`telltale.xml` is a Docker template for Unraid's Docker page (and Community Applications).
`telltale.png` is its icon.

**Install** (Unraid 6.10 or later):

1. Get the template onto the server, from the Unraid terminal:
   ```sh
   curl -fsSL -o /boot/config/plugins/dockerMan/templates-user/my-TelltaleDNS.xml \
     https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/unraid/telltale.xml
   ```
2. Optional, a starter config (encrypted upstreams, one balanced blocklist, a 7-day query log):
   ```sh
   mkdir -p /mnt/user/appdata/telltale/config
   curl -fsSL -o /mnt/user/appdata/telltale/config/telltale.toml \
     https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/compose/telltale.toml
   ```
   Without a `telltale.toml` the built-in defaults apply.
3. **Docker → Add Container**, pick **TelltaleDNS** under *Template*, set **Fixed IP address** to a
   free address on your LAN, and **Apply**.
4. Open the web UI (the container's icon → **WebUI**) and sign in with the setup token in
   `/mnt/user/appdata/telltale/data/setup-token` (the container log names it too), or with the
   bootstrap admin you set in the template. `docker exec TelltaleDNS telltale auth setup-token`
   makes a new one.
5. Point your router's DHCP DNS server setting at the container's IP.

**What the template sets up**

| | |
|---|---|
| Network | `br0`: the container gets its own LAN address, so every device shows up as itself and port 53 doesn't clash with the Unraid host. Bridge works too (map port 53), but can hide client addresses; host networking needs port 53 free on the server (VMs' `dnsmasq` may hold it). |
| `/mnt/user/appdata/telltale/config` → `/etc/telltale` (read-only) | `telltale.toml`. Reload after editing: `docker kill -s HUP TelltaleDNS`. |
| `/mnt/user/appdata/telltale/data` → `/var/lib/telltale` | Lists, the query log, users: the only path written to. Back it up with your appdata. |
| `/mnt/user/appdata/telltale/secrets` → `/run/secrets` (read-only, advanced) | Files for `*_file` settings, such as `password_file = "/run/secrets/smtp-password"`. |
| Ports | 53 UDP/TCP (DNS), 8053 (web UI and API), 9153 (Prometheus metrics). |
| Variables | `TELLTALE_LOG`; `TELLTALE_BOOTSTRAP_ADMIN_USER` with `..._PASSWORD` or `..._PASSWORD_HASH` for the first admin (read only while no user exists). |
| Extra parameters | `--user 0:0 --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges`, as in `deploy/compose`: root inside the container (so it can write to the appdata folders Unraid creates as root) with no other capability. |

**Notes**

- The image has no shell, so the Docker page's **Console** doesn't open. Use
  `docker exec TelltaleDNS telltale <command>` from the Unraid terminal.
- With `br0`, the Unraid server itself can't reach the container unless **Settings → Docker →
  Host access to custom networks** is enabled. Turn that on if Unraid should use TelltaleDNS too.
- Updates: the Docker page shows *update ready* when a new `latest` is out; `:edge` follows main,
  and `:X.Y.Z` pins a release (edit *Repository*).
- To run as the image's unprivileged user instead, `chown -R 65532:65532 /mnt/user/appdata/telltale`
  and change `--user 0:0` to `--user 65532:65532` (with `br0` or bridge, port 53 still works).

Everything else (configuration, blocking, devices, clustering) is in
[docs/running.md](../../docs/running.md).
