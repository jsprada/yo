#!/usr/bin/env bash
# yo! server installer — Debian 12/13 (also works on recent Ubuntu LTS).
#
# Run as root over SSH on a fresh box:
#     scp deploy/install.sh root@yo.example.com:
#     ssh root@yo.example.com 'bash install.sh --host yo.example.com'
#
# Safe to re-run: every step checks what is already in place.
#
# What it does (in order):
#   1. installs prerequisites (build tools, Rust, chrony, nftables, fail2ban,
#      unattended-upgrades, sqlite3)
#   2. creates the `yo` service user and data directory
#   3. clones (or updates) the repository and builds yo-server
#   4. initializes the server (certificate + pin + server.toml)
#   5. installs a hardened systemd unit and starts the service
#   6. configures nftables (SSH + 7443 only, rate limit), fail2ban, chrony
#   7. configures unattended OS upgrades (security + updates, auto-reboot)
#   8. hardens SSH to key-only login (only if a key is already authorized)
#   9. installs the backup cron job and the `yo-server-update` script
#  10. prints the `yo init …` line to hand to each person
#
# Settings are written to /etc/yo-server/install.conf for the updater.

set -euo pipefail

# ── defaults (override with flags) ───────────────────────────────────────────
HOST=""
PORT=7443
REPO="https://github.com/jsprada/yo"
BRANCH="main"
ADMIN=""
OPEN_REGISTRATION=0
AUTO_UPDATE=0
YES=0

SRC_DIR=/opt/yo
DATA_DIR=/var/lib/yo-server
CONF_DIR=/etc/yo-server
BIN=/usr/local/bin/yo-server
UPDATE_BIN=/usr/local/sbin/yo-server-update
BACKUP_DIR=/var/backups/yo-server
DEPLOY_KEY=/root/.ssh/yo_deploy_ed25519
MARKER="# managed by yo-server install.sh"

usage() {
  cat <<EOF
Usage: install.sh [options]

  --host NAME        DNS name clients connect to (asked for if omitted)
  --port N           TCP port (default $PORT)
  --repo URL         git repository (default $REPO)
  --branch NAME      branch to build (default $BRANCH)
  --admin USER       also create a sudo user with your SSH key
  --open             open registration (default: tokens required)
  --auto-update      weekly timer that rebuilds yo-server from the branch
  --yes              non-interactive: accept defaults, never prompt
  -h, --help         this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --admin) ADMIN="$2"; shift 2 ;;
    --open) OPEN_REGISTRATION=1; shift ;;
    --auto-update) AUTO_UPDATE=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

interactive() { [ "$YES" -eq 0 ] && [ -t 0 ]; }

# ask "prompt" "default" → prints the answer
ask() {
  local prompt="$1" default="${2:-}" answer
  if ! interactive; then
    printf '%s' "$default"
    return
  fi
  if [ -n "$default" ]; then
    read -r -p "$prompt [$default]: " answer
  else
    read -r -p "$prompt: " answer
  fi
  printf '%s' "${answer:-$default}"
}

# confirm "question" → 0 for yes; non-interactive answers yes
confirm() {
  interactive || return 0
  local a
  read -r -p "$1 [y/N] " a
  [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]
}

export DEBIAN_FRONTEND=noninteractive
export PATH="/root/.cargo/bin:$PATH"

[ "$(id -u)" -eq 0 ] || die "run as root (sudo -i)"

# ── 0. sanity ─────────────────────────────────────────────────────────────────
log "Checking the system"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    debian:12|debian:13) ok "Debian $VERSION_ID" ;;
    ubuntu:22.04|ubuntu:24.04) ok "Ubuntu $VERSION_ID" ;;
    *) warn "untested OS: ${PRETTY_NAME:-unknown}"; confirm "Continue anyway?" || exit 1 ;;
  esac
else
  die "cannot read /etc/os-release"
fi
command -v systemctl >/dev/null || die "systemd is required"

if [ -z "$HOST" ]; then
  guess="$(hostname -f 2>/dev/null || true)"
  HOST="$(ask "DNS name clients will connect to (e.g. yo.example.com)" "$guess")"
fi
[ -n "$HOST" ] || die "--host is required"
if ! getent ahosts "$HOST" >/dev/null 2>&1; then
  warn "'$HOST' does not resolve yet; the certificate will still be issued for it"
  confirm "Continue?" || exit 1
fi

# ── 1. packages ───────────────────────────────────────────────────────────────
log "Installing prerequisites"
need=()
for p in build-essential pkg-config git curl ca-certificates sudo chrony fail2ban python3-systemd \
         nftables unattended-upgrades sqlite3 gnupg; do
  dpkg -s "$p" >/dev/null 2>&1 || need+=("$p")
done
if [ ${#need[@]} -gt 0 ]; then
  apt-get update -q
  apt-get install -y -q "${need[@]}"
  ok "installed: ${need[*]}"
else
  ok "all packages present"
fi

log "Rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
  ok "rustup installed"
fi
# yo! needs 1.85+; keep stable current.
rustup update stable >/dev/null 2>&1 || true
ok "$(rustc --version)"

# ── 2. service user ───────────────────────────────────────────────────────────
log "Service user"
if ! id yo >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin yo
  ok "created user yo"
else
  ok "user yo exists"
fi
install -d -m 0700 -o yo -g yo "$DATA_DIR"
install -d -m 0755 "$CONF_DIR"

# ── 3. source ─────────────────────────────────────────────────────────────────
log "Source code ($REPO, branch $BRANCH)"
GIT_SSH=""
if [ -f "$CONF_DIR/install.conf" ]; then
  # shellcheck disable=SC1090
  . "$CONF_DIR/install.conf"
  [ -n "${GIT_SSH_COMMAND:-}" ] && GIT_SSH="$GIT_SSH_COMMAND"
fi

setup_deploy_key() {
  # Private repository: use a read-only deploy key.
  if [ ! -f "$DEPLOY_KEY" ]; then
    install -d -m 0700 /root/.ssh
    ssh-keygen -q -t ed25519 -N "" -C "yo-server deploy key $(hostname)" -f "$DEPLOY_KEY"
  fi
  GIT_SSH="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
  case "$REPO" in
    https://github.com/*) REPO="ssh://git@github.com/${REPO#https://github.com/}" ;;
  esac
  cat <<EOF

The repository looks private. Add this read-only deploy key on GitHub
(Settings → Deploy keys → Add deploy key; leave "Allow write access" off):

$(cat "$DEPLOY_KEY.pub")

EOF
  if interactive; then
    read -r -p "Press Enter once the key is added… "
  else
    die "add the deploy key above, then re-run (non-interactive mode cannot wait)"
  fi
}

clone_or_update() {
  if [ -d "$SRC_DIR/.git" ]; then
    git -C "$SRC_DIR" remote set-url origin "$REPO"
    GIT_SSH_COMMAND="$GIT_SSH" git -C "$SRC_DIR" fetch -q origin "$BRANCH"
    git -C "$SRC_DIR" checkout -q "$BRANCH"
    GIT_SSH_COMMAND="$GIT_SSH" git -C "$SRC_DIR" pull -q --ff-only origin "$BRANCH"
  else
    GIT_SSH_COMMAND="$GIT_SSH" git clone -q --branch "$BRANCH" "$REPO" "$SRC_DIR"
  fi
}

git_err="$(mktemp)"
if ! clone_or_update 2>"$git_err"; then
  cat "$git_err" >&2
  case "$REPO" in
    https://github.com/*)
      if grep -qiE "authentication failed|could not read Username|repository not found|terminal prompts disabled" "$git_err"; then
        setup_deploy_key
        clone_or_update || die "could not clone $REPO (see the error above)"
      else
        die "could not clone $REPO (see the error above)"
      fi ;;
    *) die "could not clone $REPO (see the error above)" ;;
  esac
fi
rm -f "$git_err"
ok "at $(git -C "$SRC_DIR" rev-parse --short HEAD) ($(git -C "$SRC_DIR" log -1 --format=%s | cut -c1-60))"

# ── 4. build ──────────────────────────────────────────────────────────────────
log "Building yo-server (a few minutes on a small VPS)"
( cd "$SRC_DIR" && cargo build --release -p yo-server -q )
if [ -f "$BIN" ] && ! cmp -s "$SRC_DIR/target/release/yo-server" "$BIN"; then
  cp -p "$BIN" "$BIN.prev"
fi
install -m 0755 -o root -g root "$SRC_DIR/target/release/yo-server" "$BIN"
ok "$("$BIN" --version)"

# ── 5. initialize ─────────────────────────────────────────────────────────────
log "Server configuration"
if [ ! -f "$DATA_DIR/server.toml" ]; then
  args=(--host "$HOST" --port "$PORT")
  [ "$OPEN_REGISTRATION" -eq 1 ] && args+=(--open)
  runuser -u yo -- "$BIN" --dir "$DATA_DIR" init "${args[@]}" >/dev/null
  # Dual-stack listen; the server canonicalises IPv4-mapped addresses.
  sed -i "s/^listen = .*/listen = \"[::]:$PORT\"/" "$DATA_DIR/server.toml"
  ok "initialized for $HOST (certificate, pin, server.toml)"
else
  ok "server.toml exists; leaving it alone"
fi
chmod 600 "$DATA_DIR/server.key" 2>/dev/null || true
chown -R yo:yo "$DATA_DIR"

# ── 6. systemd unit ───────────────────────────────────────────────────────────
log "systemd service"
cat > /etc/systemd/system/yo-server.service <<EOF
$MARKER
[Unit]
Description=yo! relay server
Documentation=https://github.com/jsprada/yo
After=network-online.target
Wants=network-online.target

[Service]
User=yo
Group=yo
ExecStart=$BIN --dir $DATA_DIR run
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q yo-server
systemctl restart yo-server
sleep 2
systemctl is-active -q yo-server || { journalctl -u yo-server -n 20 --no-pager; die "yo-server failed to start"; }
ok "yo-server running"

# ── 7a. nftables ──────────────────────────────────────────────────────────────
log "Firewall (nftables)"
ssh_ports="$( (sshd -T 2>/dev/null || true) | awk '/^port /{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//')"
ssh_ports="${ssh_ports:-22}"
if [ -f /etc/nftables.conf ] && ! grep -q "$MARKER" /etc/nftables.conf; then
  cp -p /etc/nftables.conf "/etc/nftables.conf.bak.$(date +%s)"
  warn "existing /etc/nftables.conf backed up and replaced"
fi
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
$MARKER
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    tcp dport { $ssh_ports } accept

    # yo!: an address opening more than 30 new connections/min is dropped
    tcp dport $PORT ct state new limit rate over 30/minute burst 60 packets drop
    tcp dport $PORT accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
nft -c -f /etc/nftables.conf || die "nftables rules failed validation"
nft -f /etc/nftables.conf
systemctl enable -q --now nftables
ok "open ports: ssh ($ssh_ports), yo ($PORT); everything else dropped"

# ── 7b. fail2ban ──────────────────────────────────────────────────────────────
log "fail2ban"
cat > /etc/fail2ban/filter.d/yo-server.conf <<'EOF'
[Definition]
failregex = registration refused device=\S+ ip=<HOST>
journalmatch = _SYSTEMD_UNIT=yo-server.service
EOF
cat > /etc/fail2ban/jail.d/yo-server.conf <<EOF
$MARKER
[yo-server]
enabled  = true
backend  = systemd
port     = $PORT
maxretry = 5
findtime = 10m
bantime  = 1h
banaction = nftables-multiport
EOF
systemctl enable -q --now fail2ban
systemctl restart fail2ban
ok "jail yo-server active"

# ── 7c. time sync ─────────────────────────────────────────────────────────────
log "Time sync"
systemctl enable -q --now chrony
ok "chrony running"

# ── 8. unattended upgrades ────────────────────────────────────────────────────
log "Unattended OS upgrades (security + updates, reboot at 04:30 if required)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52yo-unattended-upgrades <<'EOF'
// managed by yo-server install.sh — upgrade everything, not only security
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-updates";
    "origin=Ubuntu,codename=${distro_codename}";
    "origin=Ubuntu,codename=${distro_codename}-security";
    "origin=Ubuntu,codename=${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::MinimalSteps "true";
EOF
systemctl enable -q --now apt-daily.timer apt-daily-upgrade.timer
ok "unattended-upgrades configured"

# ── 9. admin user (optional) ──────────────────────────────────────────────────
if [ -n "$ADMIN" ]; then
  log "Admin user $ADMIN"
  if ! id "$ADMIN" >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" "$ADMIN" >/dev/null
    ok "created $ADMIN"
  fi
  usermod -aG sudo "$ADMIN"
  if [ ! -s "/home/$ADMIN/.ssh/authorized_keys" ] && [ -s /root/.ssh/authorized_keys ]; then
    install -d -m 0700 -o "$ADMIN" -g "$ADMIN" "/home/$ADMIN/.ssh"
    install -m 0600 -o "$ADMIN" -g "$ADMIN" /root/.ssh/authorized_keys "/home/$ADMIN/.ssh/authorized_keys"
    ok "copied root's SSH key to $ADMIN"
  fi
fi

# ── 10. SSH hardening (only when a key can get you in) ────────────────────────
log "SSH hardening"
have_key=0
[ -s /root/.ssh/authorized_keys ] && have_key=1
[ -n "$ADMIN" ] && [ -s "/home/$ADMIN/.ssh/authorized_keys" ] && have_key=1
if [ "$have_key" -eq 1 ]; then
  cat > /etc/ssh/sshd_config.d/10-yo-hardening.conf <<EOF
$MARKER
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
X11Forwarding no
EOF
  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "password logins disabled (keys only)"
  else
    rm -f /etc/ssh/sshd_config.d/10-yo-hardening.conf
    warn "sshd rejected the hardening snippet; left SSH unchanged"
  fi
else
  warn "no SSH authorized key found for root${ADMIN:+ or $ADMIN}; NOT disabling password login (you'd be locked out)"
fi

# ── 11. backups ───────────────────────────────────────────────────────────────
log "Backups"
install -d -m 0700 "$BACKUP_DIR"
cat > /usr/local/sbin/yo-server-backup <<EOF
#!/bin/sh
$MARKER
set -eu
out=$BACKUP_DIR/yo-server-\$(date +%F).db
sqlite3 $DATA_DIR/yo-server.db ".backup '\$out'"
gzip -f "\$out"
find $BACKUP_DIR -name '*.db.gz' -mtime +14 -delete
EOF
chmod 0755 /usr/local/sbin/yo-server-backup
cat > /etc/systemd/system/yo-server-backup.service <<EOF
$MARKER
[Unit]
Description=Nightly yo-server database backup
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/yo-server-backup
EOF
cat > /etc/systemd/system/yo-server-backup.timer <<EOF
$MARKER
[Unit]
Description=Nightly yo-server database backup
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable -q --now yo-server-backup.timer
/usr/local/sbin/yo-server-backup
ok "nightly backup to $BACKUP_DIR at 03:00 (14 days kept); first one taken"

# ── 12. updater + settings ────────────────────────────────────────────────────
log "Updater"
install -m 0755 "$SRC_DIR/deploy/update.sh" "$UPDATE_BIN"
cat > "$CONF_DIR/install.conf" <<EOF
$MARKER
REPO="$REPO"
BRANCH="$BRANCH"
SRC_DIR="$SRC_DIR"
DATA_DIR="$DATA_DIR"
BIN="$BIN"
HOST="$HOST"
PORT="$PORT"
GIT_SSH_COMMAND="$GIT_SSH"
EOF
chmod 0600 "$CONF_DIR/install.conf"
ok "$UPDATE_BIN installed; settings in $CONF_DIR/install.conf"

if [ "$AUTO_UPDATE" -eq 1 ]; then
  cat > /etc/systemd/system/yo-server-update.service <<EOF
$MARKER
[Unit]
Description=Rebuild yo-server from $BRANCH and restart if it changed
[Service]
Type=oneshot
ExecStart=$UPDATE_BIN --server --yes
EOF
  cat > /etc/systemd/system/yo-server-update.timer <<EOF
$MARKER
[Unit]
Description=Weekly yo-server update
[Timer]
OnCalendar=Sun 04:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable -q --now yo-server-update.timer
  ok "weekly auto-update timer enabled (Sundays 04:00)"
else
  ok "auto-update timer not enabled (re-run with --auto-update, or run yo-server-update by hand)"
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo
log "Done. Summary"
systemctl --no-pager --quiet is-active yo-server && ok "yo-server: active, listening on [::]:$PORT"
ok "firewall: nftables + fail2ban; time: chrony; OS updates: unattended (reboot 04:30 if needed)"
echo
runuser -u yo -- "$BIN" --dir "$DATA_DIR" info
cat <<EOF

Next steps
  1. Back up the server identity NOW (the key cannot be regenerated):
       tar czf - -C $DATA_DIR server.toml server.crt server.key \\
         | gpg --symmetric --cipher-algo AES256 > /root/yo-server-identity.tgz.gpg
     …and copy that file off this machine.
  2. Add the same two ports (ssh, $PORT) to your provider's cloud firewall.
  3. Create one registration token per person:
       sudo -u yo yo-server --dir $DATA_DIR token create --note "alice"
     and send them the line above with the token filled in, over a channel you trust.
  4. Later: yo-server-update            # rebuild from $BRANCH + OS packages
            yo-server-update --check    # just report what would change
            journalctl -u yo-server -f  # watch it run
EOF
