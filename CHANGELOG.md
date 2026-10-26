# Changelog

All notable changes to yo! are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (administration from a client)

- Devices can be administrators: `yo admin token [--uses N] [--note T]` mints
  a registration token and prints the full `yo init` line; `yo admin tokens`,
  `yo admin revoke`, `yo admin status` (version, uptime, counts, abuse
  counters). Requests go over the existing mTLS connection; the only check is
  an `admin` flag on the device's registration, which deregistration clears.
  Rate-limited (10/min) and logged. Client-minted tokens never grant admin.
- Server side: `yo-server token create --admin` (the registering device
  becomes an administrator), `yo-server admin grant|revoke|list`.

### Added (status page)

- `yo-status`: an optional read-only HTTPS page for a server — what yo! is,
  a link to the source, a green/yellow/red LED, the deployed version (with
  git SHA), uptime and last-check time. It polls `yo-server` once a minute
  over a new local Unix status socket (`status_socket` in `server.toml`;
  answers one JSON line, reads nothing) and serves from memory. GET-only, no
  JavaScript, strict CSP. Let's Encrypt via TLS-ALPN-01 on 443 (no port 80),
  or own certificate / self-signed. `install.sh --status-site DOMAIN`;
  `yo-server-update` sets a maintenance marker around restarts (yellow).
- `yo-server --version` and the status page include the git SHA the binary
  was built from when built by the deploy scripts.

### Changed (deployment)

- `yo-server` prefers `/var/lib/yo-server` as its data directory when that
  exists and no `--dir`/`YO_SERVER_DIR` is given, and the installer exports
  `YO_SERVER_DIR` for login shells, so a bare `yo-server token create` acts on
  the running server instead of an empty per-user directory.

### Added (deployment)

- `deploy/install.sh`: one-shot, re-runnable installer for Debian 12/13 —
  prerequisites, Rust, service user, clone (deploy key for private repos),
  build, init, hardened systemd unit, nftables, fail2ban, chrony, unattended
  OS upgrades with auto-reboot, safe SSH hardening, backups, and the updater.
- `deploy/update.sh` (installed as `yo-server-update`): rebuilds from the
  branch with automatic rollback if the new binary fails to start; `--check`,
  `--server`, `--os`, `--test`; optional weekly timer.

### Docs

- `DEPLOYMENT.md`: a copy-paste runbook with every command and config file
  (nftables, systemd unit, fail2ban, backups, tokens, client setup).
- First deployment checklist (`docs/src/server/deploy.md`): recommended
  infrastructure, ordered steps for the box, the service, backups, the first
  two clients, day-one verification and a symptom table.

### Security

Phase 4 (L-3 completion) of the remediation plan in `SECURITY_REVIEW.md`;
details and verification in `SECURITY_REMEDIATION.md`.

- **L-3 (fixed)** Conversation keys can be rotated: `yo rekey <name>` /
  `yo rekey --all`, and `yo devices remove` rotates every key by default
  (`--no-rekey` to skip). The announcement to a contact is signed by the old
  and the new key; the old inbox is retired but what was queued there still
  arrives, and a contact who sends before syncing retries automatically.
  Rotating the device-sync key also rotates the key that authorizes
  deregistering your devices (the server accepts a replacement authority
  only when the current one signs for it). A deregistered device's live
  connections are now dropped at their next request.

### Earlier — Phase 3 of the remediation plan in `SECURITY_REVIEW.md`; details and
verification in `SECURITY_REMEDIATION.md`.

- **L-3 (mitigated)** `yo devices remove` now also deregisters the device on
  the server, cutting off its access. Each device binds, at setup, the key
  allowed to deregister it (your account identity key), so only your own
  devices can do it and a stolen *locked* device is fully cut off. A stolen
  *unlocked* device still requires burning the conversations (re-keying is
  future work).
- **L-4** Message drafts are written under `$XDG_RUNTIME_DIR` (RAM) when
  available, and vim-family editors are launched with swap/undo/backup off.
- **L-5** When a message's claimed send time disagrees with when it was
  received, `yo read` shows the received time too.
- **L-7** Values embedded in generated service files (the executable path,
  `YO_HOME`) are escaped per format, and control characters are refused.
- **I-1** Clients accept more than one certificate pin (`extra_pins`) so a
  self-signed certificate can be rotated without lock-outs; GitHub Actions in
  CI are pinned to commit SHAs. The replayable-`DeleteInbox` and same-user
  agent items are accepted with rationale (see `SECURITY_REMEDIATION.md`).

### Added (operations)

- `yo-server` logs a one-line abuse-counter summary once a minute
  (`metrics accepted=… refused_ip=… …`) for scraping and alerting (3.6).

### Earlier — Phase 2 of the remediation plan in `SECURITY_REVIEW.md`; details and
verification in `SECURITY_REMEDIATION.md`.

- **M-3** The Olm fallback key is rotated (after a week, or sooner when
  one-time keys run low), keeping the previous key for one more period so
  in-flight session openings still decrypt.
- **M-4** `yo link` now shows the joining device's id and requires approval
  on the existing device before any account secret is sent (`--yes` to skip).
  Link codes have four words (~41 bits) and expire in five minutes.
- **M-5** Failed registration attempts are throttled per IP, and a token is
  consumed in the same transaction that registers the device, so a failure
  can't burn a token.
- **L-1** The server accepts a device list only if every device in it is
  registered, so nobody can queue envelopes for a stranger's device.
- **L-2** All server database work runs on a pool of connections off the
  async runtime, so a slow query no longer stalls other connections.
- **L-6** The unread counter ignores spooled envelopes addressed to inboxes
  this device doesn't have (the daemon reads a small plaintext inbox index).

### Earlier — Phase 1 of the remediation plan in `SECURITY_REVIEW.md`; details and
verification in `SECURITY_REMEDIATION.md`.

- **H-1** Server abuse limits, configurable in a new `[limits]` table of
  `server.toml`: concurrent and new-connection limits per IP (enforced
  before the TLS handshake), concurrent connections per device, an hourly
  sending budget per device, a queue quota per recipient device, and a cap
  on live invite mailboxes (with 16 KiB mailbox messages).
- **M-1** Invite mailboxes are bound to the device that opened and the device
  that joined them; anyone else gets `Unauthorized`. Nameplates now have at
  least five digits, so codes look like `48213-crossbow-marble-tundra`.
- **M-2** Message text is sanitized before it reaches the terminal: control
  characters, C1 controls and bidirectional overrides become `�`.
- **M-6 (new)** `Fetch` responses are paged at 1 MiB and sends are chunked,
  so a backlog of large messages can no longer exceed the 2 MiB frame limit
  and stall delivery to a device.
- The server logs refused registrations as
  `registration refused device=… ip=…` for fail2ban, and disables ANSI
  colors when stderr is not a terminal.

### Changed

- Maximum message length is 64,000 bytes (was 65,536) so every normal message
  fits the 64 KiB padding bucket.

### Added

- `SECURITY_REVIEW.md`: a security review of 0.1.0 (threat model, findings
  H-1 … I-1, OWASP/CWE coverage, business-logic review, remediation plan).
  Also published in the docs under Reference.

### Changed

- The server is supported on Linux only; the client is built and tested on
  Linux, macOS and Windows. CI now reflects that.
- The dependency audit in CI runs `cargo audit` directly and fails only on
  vulnerabilities (not on "unmaintained" advisories).

### Fixed

- Windows build: the Unix-only prompt-snippet test module no longer trips
  `unused_imports` under `-D warnings`.

## [0.1.0] - 2026-10-25

First version.

### Added

- **Server (`yo-server`)**: `init` (self-signed certificate with pin, or a
  CA certificate), `run`, `info`, `stats`, and registration tokens
  (`token create|list|revoke`). Stores only ciphertext, public keys and signed
  device lists. Envelopes are deleted on acknowledgement or after 30 days.
  Invite mailboxes live only in memory. Rate limits on invites, key claims
  and sends.
- **Transport**: TLS 1.3 only, mutual authentication with Ed25519
  certificates, server key pinning (`sha256:…`), ALPN `yo/1`.
- **End-to-end encryption**: Olm (vodozemac) with a separate Olm account per
  device *per conversation*. Signed one-time and fallback keys, padding to
  size buckets.
- **Per-contact keys**: each conversation has its own identity key (RIK),
  storage key (RSK) and server inbox. Signed, versioned device lists with
  rollback protection.
- **Key exchange**: `yo add` with a single-use, 10-minute code
  (`7-crossbow-marble-tundra`) using SPAKE2 with key confirmation. Optional
  QR display. `yo verify` safety words.
- **Messaging**: `yo <name> <message>`, `$EDITOR`/stdin composing,
  `yo read`, `yo reply <#>` with quoted context, `yo history`,
  `yo contacts`, `yo rename`, typo suggestions.
- **Local encryption**: Argon2id passphrase → data key. Every sensitive
  column is sealed with XChaCha20-Poly1305 and bound to its row. Uses
  `secure_delete` and no WAL files. Message numbers are never reused.
- **Burn**: `yo burn <name>` sends a signed burn notice to both sides'
  devices, deletes the inbox on the server, and crypto-shreds the
  conversation locally. Receivers comply automatically. `--local` works
  offline.
- **Multiple devices**: `yo link` / `yo init --link`, `yo devices`,
  `yo devices remove`. Contact additions, renames, burns and sent messages
  sync between your devices.
- **Daemon & agent**: `yo daemon run|start|stop|status|install|uninstall`
  (systemd user unit, launchd agent, Windows logon task). Passphrase cache
  with a sliding timeout (`yo unlock`, `yo lock`). The notifier spools
  encrypted envelopes without needing the passphrase.
- **Prompt indicator**: `yo prompt bash|zsh|fish|powershell [--sync]` prints
  a snippet that reads an unread counter with shell builtins only.
- **Robustness**: interrupted `yo init` and `yo add` can simply be re-run
  (setup completes atomically by writing `config.toml` last, and reuses an
  already-registered device certificate). A connection whose request was
  cancelled mid-flight is discarded instead of being reused out of sync.
- **Tests**: unit tests per crate, end-to-end tests against an in-process
  server (including a plaintext scan of every database), randomized decoder
  tests, and prompt snippet tests.
- **Docs**: mdBook site in `docs/` covering server setup, client setup,
  contacts, every feature, a command reference (checked against the CLI by a
  test), the security model and the wire protocol.
