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
| M-3 | Fallback key never rotated | Medium | Open (Phase 2) | | |
| M-4 | `yo link` hands over the account on the code alone | Medium | Open (Phase 2) | | |
| M-5 | Registration-token attempts not rate-limited | Medium | Open (Phase 2) | | |
| M-6 | *(new)* Large backlogs exceeded the frame limit and stalled delivery | Medium | **Fixed** | 2026-10-25 | [§1.4](#14-m-6-new-fetch-responses-could-exceed-the-frame-limit) |
| L-1 | Device lists may name devices that never joined | Low | Open (Phase 2) | | |
| L-2 | Serialized database access | Low | Open (Phase 2) | | |
| L-3 | Removed devices keep conversation keys | Low | Open (Phase 3) | | |
| L-4 | Draft written to disk in the clear | Low | Open (Phase 3) | | |
| L-5 | Sender-controlled timestamps | Low | Open (Phase 3) | | |
| L-6 | Undecryptable envelopes count as unread | Low | Open (Phase 2) | | |
| L-7 | Service installers don't escape paths | Low | Open (Phase 3) | | |
| I-1 | Informational items | Info | Open (Phase 3) | | |

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

## 2. Phase 2 — next release

Not started. Items: M-3, M-4, M-5, L-1, L-2, L-6 (see the review's plan).

## 3. Phase 3 — hardening

Not started. Items: L-3, L-4, L-5, L-7, I-1, abuse metrics, independent audit.
