# yo! Security Remediation Log

This is the audit trail for the findings in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).
**The review itself is frozen as written on 2026-10-25 and is never edited.**
Every change made in response to it is recorded here, with what changed, how
it was verified, and the commit that carried it.

Conventions: one entry per finding, newest at the bottom of its section.
Status is one of *Open*, *Fixed*, *Mitigated* (risk reduced, residual noted),
*Accepted* (deliberately not fixed, with reasoning), or *Superseded*.

## Status overview

| ID | Finding | Severity | Status | Fixed on | Entry |
|---|---|---|---|---|---|
| H-1 | Resource exhaustion on the server | High | **Fixed** | 2026-10-25 | [§1.1](#11-h-1-resource-exhaustion-on-the-server) |
| M-1 | Invite mailboxes not bound to participants | Medium | **Fixed** | 2026-10-25 | [§1.2](#12-m-1-invite-mailboxes-are-not-bound-to-their-participants) |
| M-2 | Terminal control sequences in messages | Medium | **Fixed** | 2026-10-25 | [§1.3](#13-m-2-terminal-control-sequences-in-messages) |
| M-3 | Fallback key never rotated | Medium | **Fixed** | 2026-10-26 | [§2.1](#21-m-3-fallback-key-rotation) |
| M-4 | `yo link` hands over the account on the code alone | Medium | **Fixed** | 2026-10-26 | [§2.2](#22-m-4-yo-link-confirmation) |
| M-5 | Registration-token attempts not rate-limited | Medium | **Fixed** | 2026-10-26 | [§2.3](#23-m-5-registration-throttling-and-atomic-token-use) |
| M-6 | *(new)* Large backlogs exceeded the frame limit and stalled delivery | Medium | **Fixed** | 2026-10-25 | [§1.4](#14-m-6-new-fetch-responses-could-exceed-the-frame-limit) |
| L-1 | Device lists may name devices that never joined | Low | **Fixed** | 2026-10-26 | [§2.4](#24-l-1-device-lists-must-name-registered-devices) |
| L-2 | Serialized database access | Low | **Fixed** | 2026-10-26 | [§2.5](#25-l-2-database-off-the-async-runtime) |
| L-3 | Removed devices keep conversation keys | Low | **Mitigated** | 2026-10-26 | [§3.1](#31-l-3-device-deregistration-on-removal) |
| L-4 | Draft written to disk in the clear | Low | **Fixed** | 2026-10-26 | [§3.2](#32-l-4-drafts-off-persistent-disk) |
| L-5 | Sender-controlled timestamps | Low | **Fixed** | 2026-10-26 | [§3.3](#33-l-5-show-receive-time-on-skew) |
| L-6 | Undecryptable envelopes count as unread | Low | **Fixed** | 2026-10-26 | [§2.6](#26-l-6-unread-counter-ignores-unknown-inboxes) |
| L-7 | Service installers don't escape paths | Low | **Fixed** | 2026-10-26 | [§3.4](#34-l-7-escape-service-file-values) |
| I-1 | Informational items | Info | **Partly fixed / Accepted** | 2026-10-26 | [§3.5](#35-i-1-informational-items) |

## 1. Phase 1 — before internet exposure (2026-10-25)

Commit: `0eebd81` ("Phase 1 remediation: server abuse limits, bound mailboxes,
output sanitizing").

Plan items 1.1–1.6 of the review, plus one new finding (M-6) discovered
while implementing them. All verification tests live in
`crates/yo-cli/tests/limits.rs` unless noted, and run in CI on every push.

### 1.1 H-1: Resource exhaustion on the server

**Status: Fixed.**

**Change.** A new `[limits]` table in `server.toml` (`crates/yo-server/src/config.rs`,
`Limits`, all with defaults so existing configurations load unchanged) is
enforced in `crates/yo-server/src/server.rs`:

| Limit | Default | Where enforced |
|---|---|---|
| Concurrent connections per IP | 32 | `Server::admit_ip`, **before** the TLS handshake; the TCP connection is dropped |
| New connections per minute per IP (token bucket, burst = same) | 60 | same |
| Concurrent connections per device | 4 | after `Hello`; the client gets `RateLimited` |
| `Send` requests per minute per device | 120 (was 600) | `Server::send` |
| Ciphertext sent per device per hour | 256 MiB | `Server::charge_send` |
| Ciphertext queued per recipient device | 64 MiB | `Server::send` checks `Db::queued_bytes` for every recipient in the batch before storing anything (all-or-nothing) |
| Largest envelope | 272 KiB (was 300 KiB) | `MAX_BLOB` |
| Live invite mailboxes, server-wide | 2,000 | `Mailboxes::open` → `Full` → `RateLimited` |
| Mailbox message size | 16 KiB (was 64 KiB) | `mailbox.rs` |
| `MailboxPut`/`MailboxGet`/`MailboxClose` | 240/min per device | `Server::request` |

Connection slots are released by RAII guards (`IpGuard`, `DeviceGuard`) when
a connection ends for any reason. IPv4-mapped IPv6 addresses are canonicalised
so one host can't double its budget. Housekeeping prunes idle counters every
minute.

Operations: `docs/src/server/setup.md` §7 now documents the limits, a
fail2ban filter keyed on the new `registration refused device=… ip=…` log
line, and an nftables rate rule; the server no longer emits ANSI colour codes
when stderr isn't a terminal, so journal filters match.

**Verification.**
- `connections_per_device_are_capped`: a third connection from one device is
  refused with `RateLimited`; closing one frees a slot.
- `concurrent_connections_per_ip_are_capped`: the connection over the cap is
  dropped before TLS; closing one frees a slot.
- `new_connections_per_ip_are_rate_limited`: the bucket empties and the next
  connection is refused.
- `recipient_queue_quota`: sends are refused with "queue is full" once the
  recipient's quota is reached; the recipient drains the queue and sending
  resumes.
- `sender_hourly_quota`: the sender is refused with "hourly sending limit";
  another device is unaffected.
- `mailbox_cap`: the first `MailboxOpen` beyond the cap is refused.
- `config::tests::old_config_without_limits_still_loads`.

**Residual.** Limits are per server process (in memory); a restart resets the
hourly budgets. Distributed floods from many addresses are a network-level
concern (documented). A per-IP limit is weaker for users behind carrier-grade
NAT; raise `connections_per_ip` if such users are expected.

### 1.2 M-1: Invite mailboxes are not bound to their participants

**Status: Fixed.**

**Change.** `crates/yo-server/src/mailbox.rs` records the opener's device at
`MailboxOpen` and the joiner's at `MailboxJoin`. `MailboxPut` and
`MailboxGet` require the caller to be the device holding the requested side;
`MailboxClose` requires a participant. A second, different joiner is refused
with `AlreadyJoined` but no longer destroys the mailbox (the previous
behaviour let any registered device close any invite). An opener cannot join
its own mailbox. Nameplates are drawn from `10000..99999` (five digits,
widening under load) instead of `1..999`.

The client needs no change: codes are still `<nameplate>-word-word-word`.
Documentation examples now show five-digit codes.

**Verification.**
- `mailboxes_are_bound_to_their_participants`: a registered third device's
  put/get/close on a live invite all return `Unauthorized`, and the real
  exchange then completes with matching safety words. Also asserts
  nameplates ≥ 10,000.
- `mailbox::tests::participants_only` and `cap_and_size` (unit).

**Residual.** A third party that guesses a nameplate can still *join* first
(one SPAKE2 attempt, which fails) and thereby make the legitimate joiner's
attempt fail with "already used". With five-digit nameplates and the 20/min
join limit this is ~0.2 % per targeted invite over its 10-minute life; the
failure is visible and the users simply retry. Binding the joiner to a
device chosen by the opener would require exchanging device ids out of band
and is not planned.

### 1.3 M-2: Terminal control sequences in messages

**Status: Fixed.**

**Change.** `yo_cli::ui::clean` replaces every control character except
newline and tab (`char::is_control`, which covers C0, DEL and C1) and the
Unicode bidirectional override/isolate characters (U+202A–U+202E,
U+2066–U+2069) with U+FFFD. It is applied to message bodies in `yo read`,
`yo history` and quoted reply context (`card`, `history_line`,
`first_line`). Nicknames are never affected because they are chosen locally
and validated to a safe character set.

**Verification.** `ui::tests::control_and_bidi_characters_are_neutralized`:
an escape sequence, a BEL, a C1 CSI and an RLO are removed while newline, tab
and ordinary Unicode survive.

**Residual.** Zero-width and confusable characters are passed through; they
can't drive the terminal but could make text misleading. Not planned.

### 1.4 M-6 (new): `Fetch` responses could exceed the frame limit

**Status: Fixed.** Found while implementing 1.1.

**Description.** The frame codec enforces its 2 MiB limit when *encoding*
too. `Fetch` returned up to 200 envelopes regardless of size, and a client's
`Send` could carry up to 64 envelopes of 256 KiB. A queue holding more than
~2 MiB (a handful of maximum-size messages, deliberately or not) made every
`Fetch` for that device fail to serialize, so delivery stopped permanently
for that device. Likewise a large message to a contact with many devices
could fail to send. Severity: Medium (denial of service of one device's
delivery, triggerable by a contact; no confidentiality impact).

**Change.** `Db::fetch` pages by bytes (`FETCH_MAX_BYTES` = 1 MiB, always at
least one envelope); the client already loops until a fetch comes back empty.
The client splits `Send` into chunks of at most 1 MiB (`SEND_CHUNK_BYTES`),
and the maximum message length is 64,000 bytes so an ordinary message pads to
the 64 KiB bucket rather than the 256 KiB one.

**Verification.** `fetch_is_split_into_frame_sized_pages`: 24 large messages
(~1.5 MiB) are delivered across several pages and all 24 arrive. The e2e
suite exercises chunked sends to multi-device contacts.

### 1.5 Plan item 1.6: operations documentation

**Status: Done.** See `docs/src/server/setup.md` §7 ("Firewall and abuse
protection"): built-in limits table, fail2ban filter and jail, nftables
rate rule, and the `[limits]` reference in §4.

## 2. Phase 2 (2026-10-26)

Commit: `feca4b8` ("Phase 2 remediation: fallback rotation, link confirmation, reg throttling"). Plan items
2.1–2.6 of the review. Verification tests are in `crates/yo-cli/tests/limits.rs`
(Phase 2 section) and the crates' unit tests, and run in CI on every push.

### 2.1 M-3: Fallback key rotation

**Status: Fixed.**

**Change.** A `fallback_at` timestamp was added to each relationship bundle
(`yo-store`, `#[serde(default)]` so old stores load). `Client::rotate_fallback`
publishes a fresh batch of one-time keys *and* a new fallback key and stamps
the time; `rotate_fallback_keys(older_than)` does this for every relationship
past an age. A successful `yo sync`/`yo read` rotates keys older than 7 days
(`FALLBACK_ROTATE_SECS`); when one-time keys are found low during spool
processing, the fallback is rotated too unless it is under a day old
(`FALLBACK_ROTATE_WHEN_LOW_SECS`). vodozemac keeps the *previous* fallback key
after a rotation, so a session opened against the key just retired still
decrypts; two rotations retire it for good.

**Verification.** `fallback_key_rotation_keeps_one_previous_key`: a message
sent using alice's fallback key decrypts after one rotation; the session keeps
working after further rotations; a message whose prekey used a fallback key
that has since been rotated out twice no longer decrypts (grace period ended).

**Residual.** The window is bounded by rotation cadence, not wall-clock, so a
device that never comes online to rotate keeps an old fallback key usable.
Acceptable: such a device is also not receiving new one-time keys.

### 2.2 M-4: `yo link` confirmation

**Status: Fixed.**

**Change.** `pake_open` gained a `confirm` callback that is shown the other
side's decrypted payload *before* the opener's own payload is sent, and
aborts (closing the mailbox) if it returns false. `link_open` passes a
callback that decodes the joiner's `LinkHello` and asks the caller to approve
its device id; `yo link` prints the id and reads a `y/N` answer (or `--yes`).
The new device prints its own id on start so the two can be compared. Link
codes now use four words (`LINK_CODE_WORDS`, ~41 bits) and a five-minute
timeout (`LINK_TIMEOUT`); `parse_code` accepts three- or four-word codes.

**Verification.** `linking_needs_the_existing_devices_approval`: a declining
confirmation makes the opener abort with "cancelled", the new device gets
nothing, and the device count stays 1; also asserts link codes have four
words. The e2e linking test passes an approving callback.

**Residual.** `--yes` restores the old one-factor behaviour for scripts;
documented. A stolen *and* approved device is M-4-out-of-scope (that is L-3).

### 2.3 M-5: Registration throttling and atomic token use

**Status: Fixed.**

**Change.** `Db::use_token` + separate `register` were replaced by
`Db::register_with_token`, a single transaction that decrements the token and
inserts the registration together, so a failure consumes nothing. The server
tracks failed registrations per source IP in a one-minute window
(`failed_registrations_per_minute_per_ip`, default 5) and returns
`RateLimited` past the limit, before touching the database.

**Verification.** `failed_registrations_are_throttled_per_ip`: the third bad
attempt in a window is `RateLimited`, and a *valid* token is also made to wait
out the window; `db::tests::token_registration_is_atomic_and_single_use`: a
bad token leaves the token list untouched and the device unregistered.

### 2.4 L-1: Device lists must name registered devices

**Status: Fixed.** `Server::put_list` now checks every entry of a submitted
device list against the `registered` table and rejects the list with
`BadRequest` if any device is unknown. Combined with the mTLS-derived device
id, this means an inbox can only ever list real devices of this server.

**Verification.** `device_lists_may_only_name_registered_devices`: a list
containing an unregistered key is refused; the same list with only registered
keys is accepted.

### 2.5 L-2: Database off the async runtime

**Status: Fixed.** A `DbPool` (`crates/yo-server/src/pool.rs`) holds several
SQLite connections (WAL mode, 5 s busy timeout) and runs each operation on a
`spawn_blocking` thread. Every `Server` database call goes through it, so a
slow query occupies one connection and one blocking thread instead of blocking
the runtime or every other request. `db_connections` (default 4) is
configurable.

**Verification.** `pool::tests::queries_run_in_parallel_off_the_runtime`: 8
blocking queries over 4 connections finish in roughly 2×, not 8×, their
duration, and the async runtime stays responsive throughout.

### 2.6 L-6: Unread counter ignores unknown inboxes

**Status: Fixed.** The client writes a small plaintext index of its own inbox
ids (`Paths::inbox_index`; inbox ids are already known to the server, so this
leaks nothing new) whenever its relationships change. `spool::incoming_count`
counts only spooled envelopes from other devices whose inbox is in that index,
so junk queued to a device for an inbox it doesn't have no longer inflates the
prompt's `yo!(N)`. With no index yet, every envelope counts (old behaviour).

**Verification.** `unread_counter_ignores_envelopes_for_unknown_inboxes`: an
envelope sent (by a non-member) to a device for an unknown inbox leaves the
counter at 0, a real message raises it to 1, and the junk is dropped silently
on `yo read` without a user-visible "undecryptable" notice beyond the normal
drop handling.

## 3. Phase 3 (2026-10-26)

Commit: `<pending>` ("Phase 3 remediation"; see git history). Plan items
3.1–3.6 of the review. Verification tests are in `crates/yo-cli/tests/limits.rs`
(Phase 3 section) and crate unit tests, run in CI on every push.

### 3.1 L-3: Device deregistration on removal

**Status: Mitigated** (the locked-stolen-device case is closed; the
unlocked-device case still needs burning / re-keying, which stays future work
as the review anticipated).

**Change.** A device now tells the server, at setup, which key is allowed to
deregister it: a new `Request::BindRevocation { authority, sig }`, where
`authority` is the account's own self-identity (self-RIK) public key and the
caller signs over its own mTLS device id. The server stores it in a new
`revocation` column on `registered`, **first write wins**, so a stolen device
re-registering cannot overwrite it. `Request::Deregister { device, ts,
authority, sig }` removes a device's registration, memberships, published keys
and queued envelopes, but only if `authority` matches the device's stored
value and the signature and timestamp check out. `yo devices remove` sends a
`Deregister` (signed by the self-RIK, which every one of your devices holds)
before taking the device out of the signed device lists.

Because all of a person's devices share the self-RIK, any of them can
deregister a lost one. A **locked** stolen device cannot: its self-RIK sits in
the encrypted store, and `yo devices remove` from another device both
deregisters it and drops it from every inbox. An **unlocked** stolen device
(passphrase known) holds the self-RIK, so deregistration alone is not enough —
burning the conversations (which rotates keys) remains the documented remedy.

**Authorization reasoning.** Deregistration is gated on the specific bound
authority, not on inbox membership, so the griefing path considered during
review (create an inbox listing a victim's device, then deregister it) does
not exist: the attacker would need the victim's self-RIK. `BindRevocation`
only ever sets the *caller's own* device authority (caller == device via
mTLS), so nobody can pre-bind someone else's device.

**Metadata note.** All of a person's devices bind the same authority key,
which the server can see — it links those devices. The server can already
link them (they share a self-inbox device list and appear in the same contact
inboxes), so this is within the documented metadata exposure, now explicit.

**Verification.**
- `device_deregistration_is_authorized_and_cuts_off_access`: an outsider's
  `Deregister` with the wrong authority is `Unauthorized` and leaves access
  intact; `yo devices remove` then succeeds.
- `deregistration_requires_the_bound_authority`: a token-mode device
  deregistered via its bound authority can no longer reconnect
  (`RegistrationRequired`).
- `db::tests` cover the first-write-wins binding implicitly via the server
  tests.

### 3.2 L-4: Drafts off persistent disk

**Status: Fixed.** `edit_message` writes the draft to `Paths::runtime_dir`,
which prefers `$XDG_RUNTIME_DIR` (a per-user tmpfs on Linux) and falls back to
the data directory elsewhere, and names it `compose-<pid>.txt`. vim-family
editors (`vi`/`vim`/`nvim`/`view`) are launched with `-n -i NONE` so they
leave no swap or viminfo copy. The file is still overwritten and deleted after
use.

**Residual.** On platforms without a tmpfs runtime dir (and on the data-dir
fallback) the overwrite-then-delete is best-effort against CoW/journaling
filesystems; documented. Editors other than vim may keep their own backups.

### 3.3 L-5: Show receive time on skew

**Status: Fixed.** `ui::card` shows `(received <time>)` for an incoming
message whenever the sender's claimed `sent_at` and our `received_at` differ
by more than five minutes, so a back- or post-dated message is visible as
such. `ui::tests::receive_time_shown_only_when_it_diverges` covers both cases.

### 3.4 L-7: Escape service-file values

**Status: Fixed.** `service.rs` rejects control characters in the executable
path and `YO_HOME`, then escapes them per format: systemd values are
double-quoted with `\` and `"` escaped (`systemd_quote`), the launchd plist is
XML-escaped (`xml_escape`), and the Windows action already doubles single
quotes. A path with spaces, quotes or XML metacharacters now produces a valid
service definition or a clean refusal, never a malformed or injected one.
Self-inflicted only (the values come from the user's own environment).

### 3.5 I-1: Informational items

- **Multiple accepted pins — Fixed.** `ServerTrust::Pinned` holds a set of
  pins; `ClientConfig` gains `extra_pins`. A self-signed certificate can be
  rotated by adding the new pin, migrating, then dropping the old one, with no
  lock-out. Verified by `additional_pins_are_accepted`. Documented under
  server setup (certificate rotation).
- **SHA-pinned GitHub Actions — Fixed.** `.github/workflows/ci.yml` pins every
  action to a commit SHA with the version in a comment. `dtolnay/rust-toolchain`
  is pinned by SHA *and* given an explicit `toolchain: stable` input, since its
  ref name would otherwise select the toolchain.
- **Replayable `DeleteInbox` — Accepted.** Burning is idempotent and terminal;
  a replay has no effect. Adding nonce state to the server for zero security
  gain is not worth it.
- **Same-user agent requests — Accepted.** Any process running as your user
  while the store is unlocked can ask the agent for the key; this is inherent
  to a passphrase cache (ssh-agent / gpg-agent are the same) and already
  documented, with `yo lock` and short `--for` as the controls.
- **`YO_PASSPHRASE` in the environment, Windows pipe ACL — Accepted.** Both are
  documented limitations in the security model; unchanged.
- **Unmaintained transitive dependency on unsupported targets — Accepted.**
  `atomic-polyfill` is not in the Linux/macOS/Windows dependency trees; CI runs
  `cargo audit` on every push.

### 3.6 Abuse metrics

**Status: Done.** The running server logs a cumulative counter line once a
minute — `accepted`, `refused_ip`, `refused_device_conn`,
`refused_registration`, `rate_limited`, `live_mailboxes` — in a fixed format
for scraping. The counters hold no per-user data. Documented under server
monitoring.

### 3.7 Independent audit

**Status: Open / external.** Still recommended once the project stabilizes;
cannot be done in-tree.

## 4. Still open after Phase 3

- **L-3 (unlocked stolen device):** full conversation re-keying on device
  removal, so a removed device's keys stop working without a manual burn. The
  review budgeted this at ~3 days and it remains the main outstanding security
  improvement.
- **An independent audit of the protocol, the server and the storage format.**
