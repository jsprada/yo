#!/usr/bin/env bash
# yo-server-update — update a server installed by deploy/install.sh.
#
#   yo-server-update            rebuild yo-server from its branch, restart if
#                               it changed, then upgrade OS packages
#   yo-server-update --server   only yo-server
#   yo-server-update --os       only OS packages
#   yo-server-update --check    report what would change, change nothing
#   yo-server-update --test     run the server's test suite before installing
#   yo-server-update --yes      never prompt (what the timer uses)
#
# If the new binary fails to come up, the previous one is restored.

set -euo pipefail

CONF=/etc/yo-server/install.conf
[ -r "$CONF" ] || { echo "missing $CONF — was the server installed with install.sh?" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
: "${REPO:?}" "${BRANCH:?}" "${SRC_DIR:?}" "${DATA_DIR:?}" "${BIN:?}"
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-}"
export PATH="/root/.cargo/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive
STATUS_SITE="${STATUS_SITE:-}"
MAINT=/run/yo-server-maintenance
# The status page shows yellow while this file exists.
maintenance_on()  { : > "$MAINT"; }
maintenance_off() { rm -f "$MAINT"; }
trap maintenance_off EXIT

DO_SERVER=1; DO_OS=1; CHECK=0; TEST=0; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server) DO_SERVER=1; DO_OS=0 ;;
    --os) DO_SERVER=0; DO_OS=1 ;;
    --check) CHECK=1 ;;
    --test) TEST=1 ;;
    --yes) YES=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
confirm() { { [ "$YES" -eq 1 ] || [ ! -t 0 ]; } && return 0; local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v cargo >/dev/null || die "cargo not found; re-run install.sh"

healthy() {
  # Up, and logged that it is listening since the restart.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if systemctl is-active -q yo-server \
       && journalctl -u yo-server --since "-30s" --no-pager 2>/dev/null | grep -q "listening on"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

update_server() {
  log "yo-server: checking $REPO ($BRANCH)"
  git -C "$SRC_DIR" fetch -q origin "$BRANCH"
  local local_rev remote_rev behind
  local_rev="$(git -C "$SRC_DIR" rev-parse HEAD)"
  remote_rev="$(git -C "$SRC_DIR" rev-parse "origin/$BRANCH")"
  behind="$(git -C "$SRC_DIR" rev-list --count "HEAD..origin/$BRANCH")"
  if [ "$local_rev" = "$remote_rev" ] && cmp -s "$SRC_DIR/target/release/yo-server" "$BIN" 2>/dev/null; then
    ok "already at $(git -C "$SRC_DIR" rev-parse --short HEAD); nothing to do"
    return 0
  fi
  if [ "$behind" -gt 0 ]; then
    echo "  $behind new commit(s):"
    git -C "$SRC_DIR" log --oneline "HEAD..origin/$BRANCH" | sed 's/^/    /'
  fi
  [ "$CHECK" -eq 1 ] && return 0
  confirm "Build and install?" || { warn "skipped"; return 0; }

  git -C "$SRC_DIR" checkout -q "$BRANCH"
  git -C "$SRC_DIR" pull -q --ff-only origin "$BRANCH"
  log "building ($(git -C "$SRC_DIR" rev-parse --short HEAD))"
  export YO_GIT_SHA
  YO_GIT_SHA="$(git -C "$SRC_DIR" rev-parse --short HEAD)"
  ( cd "$SRC_DIR" && cargo build --release -p yo-server -q )
  [ -n "$STATUS_SITE" ] && ( cd "$SRC_DIR" && cargo build --release -p yo-status -q )
  if [ "$TEST" -eq 1 ]; then
    log "running the server test suite"
    ( cd "$SRC_DIR" && cargo test --release -p yo-server -q ) || die "tests failed; not installing"
  fi
  if [ -n "$STATUS_SITE" ] && ! cmp -s "$SRC_DIR/target/release/yo-status" /usr/local/bin/yo-status; then
    install -m 0755 -o root -g root "$SRC_DIR/target/release/yo-status" /usr/local/bin/yo-status
    systemctl restart yo-status
    ok "yo-status updated: $(/usr/local/bin/yo-status --version)"
  fi
  if cmp -s "$SRC_DIR/target/release/yo-server" "$BIN"; then
    ok "yo-server binary unchanged; no restart needed"
    return 0
  fi

  cp -p "$BIN" "$BIN.prev"
  install -m 0755 -o root -g root "$SRC_DIR/target/release/yo-server" "$BIN"
  log "restarting yo-server"
  maintenance_on
  systemctl restart yo-server
  if healthy; then
    maintenance_off
    ok "yo-server updated: $("$BIN" --version) — $(git -C "$SRC_DIR" log -1 --format='%h %s' | cut -c1-70)"
  else
    warn "new binary did not come up; rolling back"
    journalctl -u yo-server -n 20 --no-pager || true
    install -m 0755 "$BIN.prev" "$BIN"
    systemctl restart yo-server
    if healthy; then
      maintenance_off
      warn "previous version restored"
    else
      # Leave the marker: the page shows yellow, not red, while you look.
      warn "previous version also failing — investigate now"
      trap - EXIT
    fi
    exit 1
  fi
}

update_os() {
  log "OS packages"
  apt-get update -q
  local n
  n="$(apt-get -s full-upgrade 2>/dev/null | grep -c '^Inst' || true)"
  if [ "${n:-0}" -eq 0 ]; then
    ok "all packages current"
    return 0
  fi
  echo "  $n package(s) to upgrade"
  [ "$CHECK" -eq 1 ] && return 0
  confirm "Upgrade now?" || { warn "skipped"; return 0; }
  apt-get full-upgrade -y -q
  apt-get autoremove -y -q
  ok "packages upgraded"
  if [ -f /var/run/reboot-required ]; then
    warn "a reboot is required (unattended-upgrades will do it at 04:30, or: reboot)"
  fi
}

[ "$DO_SERVER" -eq 1 ] && update_server
[ "$DO_OS" -eq 1 ] && update_os
exit 0
