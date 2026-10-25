# Status page (`yo-status`)

An optional, read-only HTTPS page on the same machine as `yo-server` that
tells visitors what yo! is, links to the source, and shows whether the server
is up:

- 🟢 **green** — the server answered its status socket
- 🟡 **yellow** — an update or restart is in progress (or the page just started)
- 🔴 **red** — the server is not answering and no maintenance is in progress

plus the deployed version (e.g. `0.1.0 (a2012fc)`), the server's uptime,
the server address to put in `yo init`, and when the page last checked.

```text
 yo!
 Private, end-to-end encrypted messages from your terminal.

 ● Up and running
   The server answered on its local status socket.
   Deployed version   0.1.0 (a2012fc)
   Protocol           1
   Server uptime      3d 4h 12m
   Server             yo.example.com:7443
   Last checked       2026-10-26 09:41:00 UTC (12s ago)
```

## How it stays safe

- **It talks to the server over a local Unix socket, never the network.**
  `yo-server` exposes `/run/yo-server/status.sock` (configured by
  `status_socket` in `server.toml`), answers one JSON line — version,
  protocol, start time — and reads nothing. The socket is group-only; the
  page runs as its own user, `yo-status`, whose only privilege is membership
  of the `yo` group. It cannot read the database, the certificate key or
  anything else.
- **Page views never touch the server.** The page polls the socket once a
  minute (`poll_seconds`) into memory and serves from that, so it cannot be
  used to load the server.
- **Read-only, script-free.** `GET` only (`/`, `/status.json`, `/healthz`);
  anything else is 404/405. No JavaScript: the page refreshes with a `<meta>`
  tag. Strict `Content-Security-Policy`, `X-Frame-Options: DENY`, HSTS.
- **HTTPS without opening port 80.** Certificates come from Let's Encrypt via
  the TLS-ALPN-01 challenge, which runs on 443 itself, so the firewall opens
  only 22, 443 and 7443. Renewal is automatic.
- **Same sandbox as the server:** a hardened systemd unit with the single
  capability needed to bind 443.

## Install

With the installer:

```sh
install.sh --host yo.example.com --status-site status.example.com --acme-email you@example.com
```

(`--status-site` may be the same name as `--host`; the two services use
different ports.) This builds `yo-status`, creates its user, writes
`/etc/yo-status/config.toml`, installs the unit, opens 443 in nftables, and
turns on the server's status socket. Add 443 to your provider's firewall
too.

For a test box without public DNS, `--status-tls self-signed`.

## `/etc/yo-status/config.toml`

```toml
listen = "[::]:443"
status_socket = "/run/yo-server/status.sock"
maintenance_file = "/run/yo-server-maintenance"   # yellow while it exists
poll_seconds = 60
server_address = "yo.example.com:7443"             # shown on the page
github = "https://github.com/jsprada/yo"

[tls]
mode = "acme"                        # acme | files | self-signed | none
domains = ["status.example.com"]
email = "you@example.com"
cache_dir = "/var/lib/yo-status/acme"
production = true                    # false → Let's Encrypt staging
```

`mode = "files"` takes `cert` and `key` (PEM) if you'd rather bring your own
certificate; `mode = "none"` is plain HTTP for local tests only.

## Yellow: maintenance

`yo-server-update` creates `/run/yo-server-maintenance` before restarting
the server and removes it once the new version passes its health check, so
the page shows yellow during an update instead of red. If the update has to
roll back and the old version also fails, the marker is left in place — the
page stays yellow while you investigate — and `journalctl -u yo-server` has
the details. To put the page in maintenance by hand: `touch
/run/yo-server-maintenance`; `rm` it when done.

## Operations

```sh
systemctl status yo-status
journalctl -u yo-status -f
curl -s https://status.example.com/status.json
```

`/status.json` is the same information as the page, for your own monitoring.
`/healthz` says whether the *page* is up (the LED, not `/healthz`, reflects
the server, so monitoring the page doesn't flap with the server).
