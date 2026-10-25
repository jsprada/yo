# First deployment checklist

A step-by-step for putting the first real `yo-server` on the internet for a
small, trusted group (you plus a handful of people), and getting two clients
talking through it. It assumes the [Server setup](setup.md) page for the
details of each command; this page is about *order* and *what to have in
place*.

Budget about two hours the first time, most of it waiting on package installs
and builds.

## Recommended infrastructure

yo-server is tiny: it relays ciphertext and keeps a small SQLite file. The
smallest VPS any provider sells is more than enough.

| | Recommendation | Why |
|---|---|---|
| **Machine** | 1 vCPU, 1 GB RAM, 10–20 GB SSD (≈ $5/month) | The server idles at a few MB of RAM; disk only holds undelivered ciphertext, capped per device by `[limits]` |
| **OS** | Debian 12 or Ubuntu 24.04 LTS, fresh install | Stable, boring, long security support; the server is only built and tested for Linux |
| **Network** | A static IPv4 **and** IPv6, one DNS name (`yo.example.com`) | Clients connect by name; the name goes into the certificate and into everyone's config |
| **Access** | SSH with keys only, password login off, root login off | The box holds nothing readable, but it holds availability and the certificate key |
| **No reverse proxy, no CDN** | Clients talk TLS straight to `yo-server` | Mutual TLS: the client certificate must reach the server. Anything that terminates TLS in front breaks it |
| **Time** | `chrony` or `systemd-timesyncd` enabled | Signed requests (burn, deregister) carry timestamps with a 24-hour tolerance; a wildly wrong clock refuses them |
| **Firewall** | Only `22/tcp` (SSH) and `7443/tcp` open | Everything else closed; see the nftables rate rule in [Server setup §7](setup.md#7-firewall-and-abuse-protection) |
| **Backups** | Nightly copy of the data directory to somewhere off the box, encrypted | Losing `server.key` means every client re-runs `yo init`; losing the DB means everyone re-adds contacts |
| **Updates** | `unattended-upgrades` (Debian/Ubuntu) for the OS | The server is a single static-ish binary; OS patches are the part that otherwise rots |

**Certificate choice:** for a trusted group, use the **self-signed certificate
with a pin** that `yo-server init` creates. It needs no domain validation, no
renewal, and the pin travels with the invitation. Choose a CA certificate
(Let's Encrypt) only if you expect to hand out invitations to people you
can't give a pin to. You can change your mind later: pin rotation is
supported (`extra_pins`).

Hardware or hosting you do **not** need: a database server, object storage, a
load balancer, Docker, Kubernetes, or a second instance. One process, one
file.

## Checklist

### A. The box (30 min)

- [ ] Provision the VPS; note its IPv4 and IPv6.
- [ ] Create the DNS records: `A yo.example.com → <v4>` and `AAAA → <v6>`.
      Wait until `dig +short yo.example.com` answers from your laptop.
- [ ] Log in, update, install the basics:
      ```sh
      apt update && apt upgrade -y
      apt install -y build-essential pkg-config chrony fail2ban nftables unattended-upgrades
      ```
- [ ] Harden SSH (`/etc/ssh/sshd_config`): `PasswordAuthentication no`,
      `PermitRootLogin prohibit-password` (or `no` once you have a sudo user),
      then `systemctl restart ssh`. Confirm you can still log in **before**
      closing the first session.
- [ ] Firewall. The minimum, with nftables (`/etc/nftables.conf`):
      ```text
      table inet filter {
        chain input {
          type filter hook input priority 0; policy drop;
          ct state established,related accept
          iif lo accept
          ip protocol icmp accept
          ip6 nexthdr icmpv6 accept
          tcp dport 22 accept
          tcp dport 7443 ct state new limit rate over 30/minute burst 60 packets drop
          tcp dport 7443 accept
        }
      }
      ```
      `systemctl enable --now nftables`, then check from your laptop that only
      22 and 7443 answer (`nmap -p 22,7443,80,443 yo.example.com`).
- [ ] `systemctl enable --now chrony` and confirm `chronyc tracking` shows a
      small offset.

### B. The server software (20 min)

- [ ] Install Rust on the box (building there avoids glibc mismatches with
      your laptop):
      ```sh
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      . "$HOME/.cargo/env"
      ```
- [ ] Clone and build the server only:
      ```sh
      git clone https://github.com/jsprada/yo && cd yo
      cargo build --release -p yo-server
      install -m 0755 target/release/yo-server /usr/local/bin/
      ```
      (If the repo is still private, use an SSH deploy key or `gh auth login`
      on the box; a read-only deploy key is the cleanest.)
- [ ] Create the service user and data directory:
      ```sh
      useradd --system --home /var/lib/yo-server --create-home --shell /usr/sbin/nologin yo
      ```
- [ ] Initialize. Use the DNS name, not the IP, so the certificate matches:
      ```sh
      sudo -u yo yo-server --dir /var/lib/yo-server init --host yo.example.com
      ```
      This prints the pin. **Copy the whole `yo init …` line somewhere safe**;
      it's what you'll send to each person.
- [ ] (Optional) Listen on both IPv4 and IPv6: edit
      `/var/lib/yo-server/server.toml` → `listen = "[::]:7443"`. The server
      treats IPv4-mapped addresses correctly for rate limits.
- [ ] Leave `registration = "token"` (the default). You will make one token
      per person.
- [ ] Install the systemd unit from [Server setup §6](setup.md#6-run-it-as-a-service-systemd),
      then:
      ```sh
      systemctl daemon-reload && systemctl enable --now yo-server
      journalctl -u yo-server -n 20
      ```
      You should see `listening on … (registration: Token)` and the pin.
- [ ] fail2ban: drop the filter and jail from [Server setup §7](setup.md#blocking-abusers-at-the-network-level)
      into `/etc/fail2ban/{filter.d,jail.d}/yo-server.conf`, then
      `systemctl restart fail2ban` and `fail2ban-client status yo-server`.

### C. Backups and upkeep (15 min)

- [ ] Back up **now**, before anyone registers:
      `/var/lib/yo-server/{server.toml,server.crt,server.key}`. Put them in
      your password manager or an encrypted archive off the box. The key is
      the one file you can't recreate without disrupting every client.
- [ ] Nightly DB backup, e.g. a root cron entry:
      ```sh
      0 3 * * * sqlite3 /var/lib/yo-server/yo-server.db ".backup /var/backups/yo-server.db" && gzip -f /var/backups/yo-server.db
      ```
      (`apt install sqlite3`.) Then ship `/var/backups/` off the box with
      whatever you already use (restic, rclone, your provider's snapshots).
      The DB holds only ciphertext and public keys, but encrypt the backup
      anyway; it reveals who-talks-to-whom.
- [ ] `dpkg-reconfigure -plow unattended-upgrades` → yes.
- [ ] Decide how you'll update `yo-server` itself: `git pull && cargo build
      --release -p yo-server && install … && systemctl restart yo-server`.
      Write it down.

### D. First two clients (20 min)

Do this with one other person, or with your laptop and a second machine.

- [ ] Make a token per person (`--uses 2` if someone has two devices):
      ```sh
      sudo -u yo yo-server --dir /var/lib/yo-server token create --note "alice"
      ```
- [ ] Send each person, **over a channel you trust** (in person, a phone
      call, or an app you already consider private), the one line from
      `init`, with their token filled in:
      `yo init --server yo.example.com:7443 --pin sha256:… --token …`
      The pin is what stops a look-alike server; treat it like the token.
- [ ] Each person installs the client with one command
      (`cargo install --git ssh://git@github.com/jsprada/yo yo-cli`; see
      [Install](../client/install.md)) and runs that line. They pick a
      passphrase. `yo status` should show `network: ok`.
- [ ] Each person: `yo daemon install`, then `yo prompt bash >> ~/.bashrc`
      (or zsh/fish/powershell) and open a new shell.
- [ ] Exchange keys: one runs `yo add bob`, reads the five-digit code aloud,
      the other runs `yo add alice <code>`. Both see `✔ … added`.
- [ ] Compare safety words once, out loud: `yo verify bob` on both sides.
- [ ] Send a message each way; confirm `yo!(1)` appears in the other
      person's prompt within a second or two, then `yo read`, `yo reply`.

### E. Day-one verification

- [ ] `journalctl -u yo-server | grep metrics` shows a line a minute with
      `refused_registration=0` and `rate_limited=0`. Anything else is someone
      poking at the port.
- [ ] `yo-server --dir /var/lib/yo-server stats` shows your devices and
      inboxes, and `queued envelopes` drops to 0 after everyone reads.
- [ ] Put the laptop to sleep for ten minutes, wake it, send a message: the
      daemon reconnects (backoff up to a minute) and the prompt updates.
      `yo daemon status` should say `connected`.
- [ ] Reboot the VPS once. `yo-server` comes back by itself; clients
      reconnect; nothing is lost.
- [ ] Restore test: copy a DB backup to a scratch directory and run
      `yo-server --dir /that/dir stats` against it. A backup you've never
      restored is a hope, not a backup.

## If something goes wrong

| Symptom | Look at |
|---|---|
| `certificate does not match your pinned fingerprint` | You regenerated `server.crt`, or sent someone the wrong pin. `yo-server info` prints the current one. Never work around this by removing the pin. |
| `needs a registration token` | The token was used up (`token list`), or `--uses` was too small. Make another. |
| Clients connect but never see messages | The daemon isn't running (`yo daemon status`) or a firewall/NAT drops idle connections: `yo-server` pings every minute, so an idle timeout under 60 s on a middlebox will cut subscriptions. |
| `rate_limited` climbing in the metrics line | Someone (possibly a misbehaving client) is over `[limits]`; `journalctl` has the device ids. |
| Burn/deregister refused with "request expired" | Clock skew over 24 h on either side. Check `chronyc tracking` on the server and the client's clock. |

More in [Troubleshooting](../troubleshooting.md).

## What this deployment does not give you (yet)

- **Prebuilt binaries.** Installing is one `cargo install` command, which
  assumes a Rust toolchain on each client machine. That is the intended
  audience; prebuilt binaries can be added later if it ever matters.
- **An independent audit.** yo!'s own protocol and server have not been
  audited; only the end-to-end encryption library has. Keep the group to
  people who understand that.
- **Metadata privacy from the server.** The operator (you) can see who talks
  to whom and when. Everyone in the group should know that too.
