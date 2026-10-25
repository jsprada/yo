# Changelog

All notable changes to yo! are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

Phase 1 of the remediation plan in `SECURITY_REVIEW.md`; details and
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
