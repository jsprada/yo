# yo! deployment runbook

Every command and configuration file needed to put a `yo-server` on a fresh
Debian 12 / Ubuntu 24.04 VPS and connect the first clients. Copy-paste in
order. The [first deployment checklist](docs/src/server/deploy.md) explains
the *why* of each step; this file is the *how*.

Replace these placeholders throughout:

| Placeholder | Meaning | Example |
|---|---|---|
| `yo.example.com` | the server's DNS name | `yo.jsprada.net` |
| `ADMIN` | your non-root login on the VPS | `johnny` |
| `203.0.113.10` / `2001:db8::10` | the VPS's public addresses | |

Conventions: `#` prompts run as root (or `sudo -i`), `$` as `ADMIN`,
`yo$` as the `yo` service user (`sudo -u yo …`).

---

## 0. The fast path: `deploy/install.sh`

Everything in sections 2–9 below is automated by one script, which is safe to
re-run and asks only for what it can't work out. From your laptop:

```sh
scp deploy/install.sh root@yo.example.com:
ssh root@yo.example.com
# install.sh --host yo.example.com --admin ADMIN
```

Options:

| Flag | |
|---|---|
| `--host NAME` | DNS name clients connect to (prompted if omitted) |
| `--port N` | listen port (default 7443) |
| `--repo URL`, `--branch NAME` | what to build (default `github.com/jsprada/yo`, `main`) |
| `--admin USER` | also create a sudo user and copy root's SSH key to it |
| `--open` | open registration instead of tokens |
| `--status-site DOMAIN` | also run the HTTPS status page on 443 (see the Status page doc) |
| `--acme-email EMAIL` | Let's Encrypt contact for that page's certificate |
| `--status-tls MODE` | `acme` (default) or `self-signed` (testing) |
| `--auto-update` | weekly timer that rebuilds `yo-server` from the branch |
| `--yes` | never prompt (accept defaults; refuses steps that need a human) |

What it sets up, checking each piece first so re-runs are no-ops: packages
and Rust; the `yo` user; a clone of the repository (for a **private** repo it
generates a read-only deploy key, prints it, and waits while you add it on
GitHub); the release build; `yo-server init`; the hardened systemd unit;
nftables (SSH + the port only, rate-limited), fail2ban, chrony; unattended OS
upgrades for security *and* regular updates with an automatic reboot at
04:30 when needed; SSH key-only login (**only if** an authorized key already
exists, so it cannot lock you out); the nightly backup; and
`/usr/local/sbin/yo-server-update`.

With `--status-site`, it also builds and starts `yo-status`, a read-only
HTTPS page (green/yellow/red LED, deployed version, link to the source) that
learns the server's state over a local socket — see
`docs/src/server/status-page.md`. Port 443 is then the third and last open
port.

It ends by printing the `yo init …` line for clients and the three things it
can't do for you: back up the server identity off the box, add the same
ports to your provider's firewall, and create tokens.

### Updating later: `yo-server-update`

```sh
# yo-server-update            # rebuild yo-server if the branch moved, restart, then OS packages
# yo-server-update --check    # report what would change
# yo-server-update --server   # yo-server only;  --os for packages only
# yo-server-update --test     # run the server test suite before installing
```

It shows the new commits before building, installs only if the binary
actually changed, and if the new binary doesn't come up within ten seconds it
restores the previous one and restarts. The OS part runs
`apt full-upgrade` + `autoremove` and tells you if a reboot is pending (the
unattended-upgrades reboot window will take care of it otherwise).

`--auto-update` at install time (or `systemctl enable --now
yo-server-update.timer` later) runs the server part every Sunday at 04:00.
Leave it off if you'd rather review commits before they go live; OS packages
update unattended either way.

The sections below are the same steps by hand, for reference and for
anything you want to do differently.

## 1. DNS (do this first; it takes time to propagate)

At your DNS provider:

```text
A     yo.example.com   203.0.113.10
AAAA  yo.example.com   2001:db8::10
```

Check from your laptop before continuing:

```sh
dig +short yo.example.com A ; dig +short yo.example.com AAAA
```

## 2. Base system

```sh
# apt update && apt full-upgrade -y
# apt install -y build-essential pkg-config git curl chrony fail2ban nftables \
      unattended-upgrades sqlite3
# adduser ADMIN && usermod -aG sudo ADMIN
# mkdir -p /home/ADMIN/.ssh && cp /root/.ssh/authorized_keys /home/ADMIN/.ssh/ \
  && chown -R ADMIN:ADMIN /home/ADMIN/.ssh && chmod 700 /home/ADMIN/.ssh
```

Open a **second** terminal and confirm `ssh ADMIN@yo.example.com` works
with your key before the next step.

### SSH hardening

```sh
# cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
X11Forwarding no
EOF
# sshd -t && systemctl restart ssh
```

### Time sync

```sh
# systemctl enable --now chrony
# chronyc tracking | grep -E 'Stratum|System time'
```

The offset should be well under a second. yo! signs some requests with a
timestamp and rejects anything more than 24 hours off.

### Automatic OS updates

```sh
# dpkg-reconfigure -plow unattended-upgrades      # answer Yes
```

## 3. Firewall (nftables)

Only SSH and yo!'s port, with a rate limit on new yo! connections.

```sh
# cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    tcp dport 22 accept

    # yo!: drop a single address that opens more than 30 new connections/min
    tcp dport 7443 ct state new limit rate over 30/minute burst 60 packets drop
    tcp dport 7443 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
# nft -f /etc/nftables.conf && systemctl enable --now nftables
# nft list ruleset | head -20
```

From your laptop, confirm only 22 and 7443 answer:

```sh
nmap -Pn -p 22,80,443,7443 yo.example.com
```

## 4. Build and install `yo-server`

Build on the box so the binary matches its C library.

```sh
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
$ . "$HOME/.cargo/env"
$ git clone https://github.com/jsprada/yo ~/yo
$ cd ~/yo && cargo build --release -p yo-server       # ~5 minutes on 1 vCPU
$ sudo install -m 0755 target/release/yo-server /usr/local/bin/yo-server
$ yo-server --version
```

### Service user and data directory

```sh
# useradd --system --home /var/lib/yo-server --no-create-home --shell /usr/sbin/nologin yo
# install -d -m 0700 -o yo -g yo /var/lib/yo-server
```

### Initialize

```sh
# sudo -u yo yo-server --dir /var/lib/yo-server init --host yo.example.com
```

It prints a block like:

```text
Created /var/lib/yo-server/server.toml

Clients connect with:

  yo init --server yo.example.com:7443 --pin sha256:uavoahcysxqo5liv366n7ogbm4rvbv3spee2rckftwozso2cfjbq --token <TOKEN>
```

**Save that `yo init` line now** (password manager). The pin is permanent
for this certificate.

### Configuration

The generated `/var/lib/yo-server/server.toml` is fine as is. Two edits worth
making:

```sh
# sed -i 's/^listen = .*/listen = "[::]:7443"/' /var/lib/yo-server/server.toml   # IPv4 + IPv6
# grep -E '^(listen|registration)' /var/lib/yo-server/server.toml
listen = "[::]:7443"
registration = "token"
```

Leave `registration = "token"`. The `[limits]` defaults suit a small group;
see `docs/src/server/setup.md` §4 if you ever need to change them.

## 5. systemd service

```sh
# cat > /etc/systemd/system/yo-server.service <<'EOF'
[Unit]
Description=yo! relay server
Documentation=https://github.com/jsprada/yo
After=network-online.target
Wants=network-online.target

[Service]
User=yo
Group=yo
ExecStart=/usr/local/bin/yo-server --dir /var/lib/yo-server run
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
RuntimeDirectory=yo-server
RuntimeDirectoryMode=0750

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/yo-server
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
# systemctl daemon-reload
# systemctl enable --now yo-server
# systemctl status yo-server --no-pager
# journalctl -u yo-server -n 5 --no-pager
```

Expected in the journal:

```text
INFO yo_server: yo-server listening on [::]:7443 (registration: Token)
INFO yo_server: certificate pin: sha256:uavoahcy…
```

## 6. fail2ban

```sh
# cat > /etc/fail2ban/filter.d/yo-server.conf <<'EOF'
[Definition]
failregex = registration refused device=\S+ ip=<HOST>
journalmatch = _SYSTEMD_UNIT=yo-server.service
EOF
# cat > /etc/fail2ban/jail.d/yo-server.conf <<'EOF'
[yo-server]
enabled  = true
backend  = systemd
port     = 7443
maxretry = 5
findtime = 10m
bantime  = 1h
banaction = nftables-multiport
EOF
# systemctl restart fail2ban
# fail2ban-client status yo-server
```

## 7. Backups

### The irreplaceable files, right now

```sh
# tar czf - -C /var/lib/yo-server server.toml server.crt server.key \
    | gpg --symmetric --cipher-algo AES256 > /root/yo-server-identity.tgz.gpg
```

Copy `/root/yo-server-identity.tgz.gpg` off the box (and the passphrase into
your password manager). `server.key` is the one file that cannot be
regenerated without every client re-running `yo init`.

### Nightly database backup

```sh
# install -d -m 0700 /var/backups/yo-server
# cat > /usr/local/sbin/yo-server-backup <<'EOF'
#!/bin/sh
set -eu
out=/var/backups/yo-server/yo-server-$(date +%F).db
sqlite3 /var/lib/yo-server/yo-server.db ".backup '$out'"
gzip -f "$out"
# keep two weeks
find /var/backups/yo-server -name '*.db.gz' -mtime +14 -delete
EOF
# chmod 0755 /usr/local/sbin/yo-server-backup
# cat > /etc/systemd/system/yo-server-backup.service <<'EOF'
[Unit]
Description=Nightly yo-server database backup
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/yo-server-backup
EOF
# cat > /etc/systemd/system/yo-server-backup.timer <<'EOF'
[Unit]
Description=Nightly yo-server database backup
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
EOF
# systemctl daemon-reload && systemctl enable --now yo-server-backup.timer
# /usr/local/sbin/yo-server-backup && ls -la /var/backups/yo-server/
```

Ship `/var/backups/yo-server/` off the box with whatever you already use
(restic, rclone, provider snapshots). It contains only ciphertext and public
keys, but it does show who talks to whom, so keep it encrypted in transit and
at rest.

### Restore test (do it once)

```sh
# mkdir /tmp/restore && gunzip -c /var/backups/yo-server/yo-server-$(date +%F).db.gz > /tmp/restore/yo-server.db
# cp /var/lib/yo-server/server.toml /var/lib/yo-server/server.crt /var/lib/yo-server/server.key /tmp/restore/
# yo-server --dir /tmp/restore stats && rm -rf /tmp/restore
```

> **Every `yo-server` command must act on the service's data directory.**
> The installer sets `YO_SERVER_DIR=/var/lib/yo-server` for login shells and
> the binary prefers that directory when it exists, but if in doubt pass
> `--dir /var/lib/yo-server` explicitly. A bare `yo-server token create`
> against the wrong directory creates a token the running server never sees.
> And don't run `yo-server run` by hand: systemd already runs it.

## 8. Registration tokens — one per person

Your own first token, with `--admin`, so that your device can mint every
later token from your laptop (`yo admin token`) without SSH:

```sh
# sudo -u yo yo-server --dir /var/lib/yo-server token create --admin --note "me"
```

Tokens for everyone else, either from the server:

```sh
# sudo -u yo yo-server --dir /var/lib/yo-server token create --note "alice"
vil2sobn3s3hozvk22au3is3bq
(valid for 1 device registration(s))
```

or, once your device is registered as an administrator, from your laptop:

```sh
$ yo admin token --note alice      # prints the whole yo init line to send
```

`--uses 2` for someone with two machines. `token list` / `token revoke
<token>` to manage them.

Send each person this **one line**, over a channel you already trust (in
person, a phone call, an app you consider private):

```text
cargo install --git https://github.com/jsprada/yo yo-cli && \
yo init --server yo.example.com:7443 --pin sha256:uavoahcy… --token vil2sobn3s3hozvk22au3is3bq
```

The pin and the token are the whole secret; whoever has them can register
one device as a "trusted" client. The pin is also what stops a look-alike
server.

## 9. Each client (the recipient runs this)

```sh
$ cargo install --git https://github.com/jsprada/yo yo-cli    # needs Rust 1.85+
$ yo init --server yo.example.com:7443 --pin sha256:… --token …   # choose a passphrase
$ yo status                                                       # network: ok
$ yo daemon install                                               # notifier + passphrase cache, starts at login
$ yo prompt bash >> ~/.bashrc && exec bash                        # or: zsh / fish / powershell
```

Then, between two people — alice shows a code, bob types it:

```sh
alice$ yo add bob               # prints e.g. 48213-crossbow-marble-tundra and waits
bob$   yo add alice 48213-crossbow-marble-tundra
alice$ yo verify bob            # both read the six words aloud once; they must match
alice$ yo bob "hello from the real server"
bob$   yo read
bob$   yo reply 1 "hello back"
```

## 10. Day-one checks

```sh
# journalctl -u yo-server --since -5m | grep metrics | tail -1
# sudo -u yo yo-server --dir /var/lib/yo-server stats
```

Expect `refused_registration=0 rate_limited=0` and, after everyone has read,
`queued envelopes: 0`.

Then:

- Suspend a laptop for ten minutes, wake it, send a message: `yo daemon
  status` should say `connected` within a minute and the prompt updates.
- `# reboot` the VPS once; `yo-server` comes back by itself and clients
  reconnect on their own.

## 11. Updating the server later

```sh
$ cd ~/yo && git pull && cargo build --release -p yo-server
$ sudo install -m 0755 target/release/yo-server /usr/local/bin/yo-server
$ sudo systemctl restart yo-server && journalctl -u yo-server -n 3 --no-pager
```

Clients update with the same `cargo install --git … yo-cli --force`. The
protocol is versioned; a mismatched pair refuses each other with a clear
message rather than misbehaving.

## 12. If you ever have to change the certificate

Don't, unless the key leaked. If you must, use pin rotation so nobody is
locked out: each client adds the new pin under `extra_pins` in `config.toml`
*before* you switch, then makes it primary afterwards. Details in
`docs/src/server/setup.md` §3.

---

### Quick reference

| What | Where |
|---|---|
| Config, cert, key, DB | `/var/lib/yo-server/` |
| Logs | `journalctl -u yo-server` |
| Abuse counters | `journalctl -u yo-server | grep metrics` |
| DB stats | `sudo -u yo yo-server --dir /var/lib/yo-server stats` |
| Tokens | `sudo -u yo yo-server --dir /var/lib/yo-server token …` |
| Client command line to hand out | `sudo -u yo yo-server --dir /var/lib/yo-server info` |
| Bans | `fail2ban-client status yo-server` |
| Backups | `/var/backups/yo-server/` (timer, nightly 03:00) |
