# Server setup

`yo-server` is a relay. It authenticates devices, stores end-to-end
encrypted envelopes until the recipient picks them up, and hosts the short
"mailboxes" used while two people exchange keys. **It never sees message
contents, contact names, or anyone's real identity**, so you can run it on a
cheap VPS without having to trust the host with your conversations. See
[Security model](../reference/security.md) for exactly what it can see.

> Deploying for the first time? The [first deployment checklist](deploy.md)
> puts these steps in order and says what to have in place around the server.

## Requirements

- A Linux machine with a public IP or DNS name. (The server is only
  built and tested for Linux; the `yo` client runs on Linux, macOS and
  Windows.)
- One open TCP port (default **7443**).
- About 10 MB of RAM per few hundred users, and a little disk for queued
  ciphertext.

## 1. Install

From source (needs Rust 1.85+):

```sh
git clone https://github.com/jsprada/yo && cd yo
cargo build --release -p yo-server
sudo install -m 0755 target/release/yo-server /usr/local/bin/
```

## 2. Initialize

```sh
sudo useradd --system --home /var/lib/yo-server --create-home yo
sudo -u yo yo-server --dir /var/lib/yo-server init --host yo.example.com
```

Output:

```text
Created /var/lib/yo-server/server.toml

Clients connect with:

  yo init --server yo.example.com:7443 --pin sha256:uavoahcysxqo5liv… --token <TOKEN>

Create a token per person with:  yo-server token create

Start the server with:  yo-server --dir /var/lib/yo-server run
```

`init` creates:

| File | What |
|---|---|
| `server.toml` | configuration (below) |
| `server.crt`, `server.key` | a self-signed Ed25519 certificate (key is mode 0600) |
| `yo-server.db` | SQLite database |

### `init` options

| Option | Meaning |
|---|---|
| `--host HOST` | Required. DNS name or IP clients use. Put in the certificate and printed in the client command. |
| `--port N` | Port to listen on (default 7443). |
| `--open` | Let anyone register without a token (default: tokens required). |
| `--cert FILE --key FILE` | Use an existing CA-issued certificate (e.g. Let's Encrypt) instead of a self-signed one. Clients then need no `--pin`. |
| `--force` | Overwrite an existing `server.toml`. |

The data directory comes from `--dir`, the `YO_SERVER_DIR` environment
variable, or by default `~/.local/share/yo-server` (Linux),
`~/Library/Application Support/yo-server` (macOS), `%APPDATA%\yo-server`
(Windows).

## 3. Certificate: pin or CA?

**Self-signed + pin (default, recommended for small groups).** Clients pin
the SHA-256 hash of the server's public key, printed as `sha256:…`. A client
with the pin refuses to talk to anything else, even a server with a valid
CA certificate. Share the pin over a channel you trust, just like the
invite command itself. `yo-server info` prints it again at any time.

> Don't regenerate `server.crt`/`server.key` once people are using the
> server: every client would refuse the new certificate (that's the point of
> pinning). Back them up.

**Rotating a pinned certificate.** If you do need to change a self-signed
certificate (key compromise, or a planned rotation), clients can trust two
pins at once so nobody is locked out mid-change:

1. Generate the new certificate and note its pin (`yo-server info` after
   swapping, or compute it separately).
2. Each person adds the new pin to `config.toml` under `extra_pins` while
   keeping the old `pin`:
   ```toml
   pin = "sha256:<old>"
   extra_pins = ["sha256:<new>"]
   ```
3. Once everyone has the new pin, switch the server to the new certificate.
   Clients keep connecting because the new pin is accepted.
4. Afterwards, make the new pin the primary `pin` and drop the old one.

**CA certificate.** If you already have certificates (e.g. from certbot):

```sh
yo-server --dir /var/lib/yo-server init --host yo.example.com \
  --cert /etc/letsencrypt/live/yo.example.com/fullchain.pem \
  --key  /etc/letsencrypt/live/yo.example.com/privkey.pem
```

Clients then run `yo init --server yo.example.com:7443` without `--pin`.
The certificate is read at start-up, so restart `yo-server` after a renewal.

## 4. `server.toml` reference

```toml
listen = "0.0.0.0:7443"        # address:port to bind ("[::]:7443" for IPv6)
public_host = "yo.example.com" # only used to print the client command
cert = "server.crt"            # relative paths are inside the data dir
key = "server.key"
pinned = true                  # false when cert is CA-issued
registration = "token"         # "token" or "open"
message_ttl_days = 30          # undelivered envelopes are deleted after this
max_devices = 16               # devices per person per conversation

[limits]                       # abuse limits; all optional, defaults shown
connections_per_ip = 32                 # concurrent, checked before TLS
new_connections_per_minute_per_ip = 60  # token bucket, burst = same number
connections_per_device = 4              # concurrent, per registered device
queue_mib_per_device = 64               # ciphertext waiting for one device
send_mib_per_hour_per_device = 256      # ciphertext one device may send per hour
sends_per_minute = 120                  # Send requests per device
mailboxes = 2000                        # live invite mailboxes, server-wide
failed_registrations_per_minute_per_ip = 5  # bad/missing-token attempts per IP
db_connections = 4                      # SQLite connections in the pool
```

Old `server.toml` files without a `[limits]` table keep working with the
defaults.

## 5. Registration tokens

With `registration = "token"`, a device can only register with a token.
Each token works for a number of registrations, then disappears.

```sh
yo-server --dir /var/lib/yo-server token create --note "for alice"            # 1 use
yo-server --dir /var/lib/yo-server token create --uses 3 --note "bob's devices"
yo-server --dir /var/lib/yo-server token list
yo-server --dir /var/lib/yo-server token revoke <TOKEN>
```

Each *device* registers once. Someone setting up a laptop and a desktop
needs a token with `--uses 2` (or two tokens). Devices that are already
registered never need a token again.

## 6. Run it as a service (systemd)

`/etc/systemd/system/yo-server.service`:

```ini
[Unit]
Description=yo! relay server
After=network-online.target
Wants=network-online.target

[Service]
User=yo
ExecStart=/usr/local/bin/yo-server --dir /var/lib/yo-server run
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/yo-server
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now yo-server
journalctl -u yo-server -f
```

Logs go to stderr. Set `RUST_LOG=debug` for more detail (e.g.
`Environment=RUST_LOG=debug` in the unit). Logs contain short device IDs
and counts, never message content.

## 7. Firewall and abuse protection

Open the TCP port, e.g. `sudo ufw allow 7443/tcp`. yo! speaks TLS 1.3 with
the ALPN identifier `yo/1`. It doesn't work behind an HTTP reverse proxy that
terminates TLS (the client certificate must reach `yo-server`). A TCP or SNI
pass-through proxy works.

### What the server enforces by itself

Anyone on the internet can start a TLS handshake, but only a registered
device gets past `Hello`; in `token` mode nobody registers without a token.
On top of that, `yo-server` enforces the `[limits]` above:

| Stage | Limit (default) | What a client sees |
|---|---|---|
| Before TLS | 32 concurrent connections and 60 new connections/min per IP | connection dropped |
| After `Hello` | 4 concurrent connections per device | `RateLimited` |
| Registration | 5 failed token attempts/min per IP | `RateLimited` |
| Sending | 120 sends/min, 256 MiB/hour per device; 64 MiB queued per recipient | `RateLimited` ("slow down", "hourly sending limit", "queue is full") |
| Invites | 20 opens/joins per minute per device, 2,000 live mailboxes, 16 KiB per message | `RateLimited` |
| Everything | 2 MiB per frame; `Fetch` pages at 1 MiB | request refused |

Invite mailboxes are bound to the two devices taking part: nobody else can
read, write or close them, and nameplates have at least five digits.

### Blocking abusers at the network level

The server logs refused registrations with the source address, in a fixed
format meant for log filters:

```text
WARN yo_server::server: registration refused device=rnthy3ui ip=203.0.113.9
```

A fail2ban filter and jail (`/etc/fail2ban/filter.d/yo-server.conf` and
`/etc/fail2ban/jail.d/yo-server.conf`):

```ini
[Definition]
failregex = registration refused device=\S+ ip=<HOST>
journalmatch = _SYSTEMD_UNIT=yo-server.service
```

```ini
[yo-server]
enabled  = true
backend  = systemd
port     = 7443
maxretry = 5
findtime = 10m
bantime  = 1h
```

For connection floods from a single address, a kernel-level rule is cheaper
than anything the server can do. With nftables:

```text
table inet filter {
  chain input {
    tcp dport 7443 ct state new limit rate over 30/minute burst 60 packets drop
    tcp dport 7443 accept
  }
}
```

## 8. Monitoring

```sh
yo-server --dir /var/lib/yo-server stats
```

```text
        registered devices: 4
              live inboxes: 9
  burned inboxes (markers): 1
          queued envelopes: 3
             one-time keys: 180
```

`stats` reports the database (it's a separate process from the running
server). The running server also logs a counter line once a minute, which is
what to scrape or alert on for abuse:

```text
INFO yo_server::server: metrics accepted=1920 refused_ip=4 refused_device_conn=0 refused_registration=7 rate_limited=1 live_mailboxes=2
```

| Field | Meaning |
|---|---|
| `accepted` | connections admitted past the per-IP gate |
| `refused_ip` | connections dropped by the per-IP limit (before TLS) |
| `refused_device_conn` | connections refused by the per-device limit |
| `refused_registration` | failed registrations (bad or missing token) |
| `rate_limited` | requests refused by a rate limit |
| `live_mailboxes` | invite mailboxes currently open |

Steadily climbing `refused_*` or `rate_limited` is the signal to tighten
`[limits]` or add a network-level block (above). The counts are cumulative
since the server started and contain no per-user information.

## 9. Backups and upgrades

- Back up `server.crt`, `server.key` and `server.toml`. Losing the key means
  every client has to re-run `yo init` with a new pin.
- `yo-server.db` holds only ciphertext and public keys. Losing it means
  queued messages are lost and everyone needs to re-add their contacts, so
  back it up too (stop the server, or use `sqlite3 yo-server.db ".backup …"`).
- Upgrading: replace the binary and restart. The wire protocol is versioned;
  a client and server with incompatible versions refuse each other with a
  clear message.

## What the server stores

| Data | Retention |
|---|---|
| Registered device IDs (hash of each device's TLS public key) | until removed manually |
| Inboxes: ID + signed device list (public keys) | until burned |
| One-time public keys | until claimed |
| Envelopes (end-to-end ciphertext, padded) | until the recipient acknowledges them, at most `message_ttl_days` |
| Burn markers | 30 days |
| Invite mailboxes | **memory only**, at most 10 minutes |
