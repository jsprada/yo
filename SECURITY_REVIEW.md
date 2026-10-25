# yo! Security Review

| | |
|---|---|
| **Date** | 2026-10-25 |
| **Version reviewed** | 0.1.0 (git `main` at the time of review) |
| **Scope** | `yo-server` (Linux, internet-facing), the `yo` client (Linux, macOS, Windows), the wire protocol, the cryptographic design, local storage, and the business logic of every feature |
| **Method** | Manual code review of every crate against the threat model, the OWASP Top 10 (2021) and the CWE/SANS Top 25; review of the test suite; `cargo audit` of all dependencies; black-box exercise of the released binaries |
| **Reviewer** | Internal review (the author, with Claude). **Not an independent audit.** |

## 1. Summary

yo!'s core privacy promise holds: **nobody who is not a device in a
conversation's signed device list can read or alter a message**, including
the server operator, the hosting provider and anyone on the network. The
end-to-end layer (Olm, via the audited `vodozemac`), per-contact identity keys,
signed and version-checked device lists, AEAD storage bound to row ids, and
the SPAKE2 invite exchange are implemented soundly, and the test suite scans
every database and config file for plaintext after a full run.

The internet-facing server is memory-safe Rust with no shell execution, no
dynamic SQL and no deserialization of untrusted structure beyond bounded
postcard frames. It responds only to clients that complete an mTLS handshake
and, in the recommended `token` mode, have been registered with a token.

The weaknesses found are about **availability and abuse by registered
devices**, not confidentiality:

| ID | Severity | Finding |
|---|---|---|
| [H-1](#h-1-resource-exhaustion-on-the-server) | **High** | No per-IP, per-device or per-recipient resource limits: a single registered device can fill the server's disk or memory, or hold all its connections |
| [M-1](#m-1-invite-mailboxes-are-not-bound-to-their-participants) | Medium | Invite mailboxes accept messages, reads and closes from any registered device, and nameplates are small numbers, so key exchanges and device linking can be disrupted |
| [M-2](#m-2-terminal-control-sequences-in-messages) | Medium | Message bodies are printed to the terminal without filtering control characters |
| [M-3](#m-3-the-fallback-key-is-never-rotated) | Medium | The Olm fallback key is published once and never rotated, weakening forward secrecy for session-opening messages once one-time keys run out |
| [M-4](#m-4-yo-link-hands-over-the-account-on-the-strength-of-the-code-alone) | Medium | `yo link` transfers every conversation's secret keys to whoever joins with the code; the existing device never confirms the new device |
| [M-5](#m-5-registration-token-attempts-are-not-rate-limited) | Medium | Registration-token guesses are not rate-limited (tokens are 128-bit, so this is a load issue, not a brute-force risk) |
| [L-1](#l-1-device-lists-may-name-devices-that-never-joined) | Low | A device list may include device ids that never agreed to join, letting a key holder queue envelopes for strangers' devices |
| [L-2](#l-2-serialized-database-access-stalls-all-connections) | Low | All server database work runs under one mutex inside async tasks |
| [L-3](#l-3-removed-devices-keep-the-conversation-keys) | Low | `yo devices remove` doesn't rotate keys, so a removed-but-unlocked device could keep participating until the conversation is burned |
| [L-4](#l-4-message-draft-written-to-disk-in-the-clear) | Low | `$EDITOR` drafts are written unencrypted and deletion isn't reliable on SSD/CoW filesystems |
| [L-5](#l-5-sender-controlled-timestamps) | Low | Sent timestamps come from the sender and are displayed as fact |
| [L-6](#l-6-undecryptable-envelopes-count-as-unread) | Low | Junk envelopes raise the prompt's unread counter until `yo read` runs |
| [L-7](#l-7-service-installers-dont-escape-paths) | Low | Service files embed the executable path and `YO_HOME` without escaping (self-affecting only) |
| [I-1](#i-1-informational) | Info | Replayable `DeleteInbox` (idempotent), pin rotation has no story, agent nuisance requests, `YO_PASSPHRASE` in the environment, Windows pipe ACL, one unmaintained transitive dependency on unsupported targets |

**Recommendation:** fix H-1, M-1 and M-2 before exposing a server to the
internet for anyone but a trusted group ([Phase 1](#phase-1-before-internet-exposure)).
The remaining items can follow in normal development
([Phases 2–3](#phase-2-next-release)).

## 2. Threat model

| Actor | Can | Cannot (verified) |
|---|---|---|
| **Network attacker** | see that a device talks to the server, when, and padded sizes; drop or delay traffic | read, alter, replay or forge messages (TLS 1.3 + Olm); impersonate the server (pinned key) |
| **Server operator / compromised server** | see device ids, inbox ids, who-sends-to-which-inbox, timing, padded sizes; drop, delay, reorder or withhold envelopes; withhold device lists; refuse service | read messages; forge messages; add a device to anyone's conversation; swap keys; roll back device lists; learn contact names; intercept an invite (SPAKE2, one guess) |
| **Registered but unrelated device** (e.g. another user of the same server) | abuse server resources (H-1); disrupt invite mailboxes (M-1); queue envelopes to inboxes whose id it knows | read or alter anyone's messages; join anyone's conversation |
| **Your contact** | send you anything in that conversation, including terminal control sequences (M-2), forged timestamps (L-5); exhaust your one-time keys (M-3) | read or affect your *other* conversations; forge messages from your other devices |
| **Someone with your disk, no passphrase** | see counts of conversations/messages, read flags, server address, unread count; download queued ciphertext using the device TLS key | read messages, names or keys (Argon2id + XChaCha20-Poly1305) |
| **Someone with an unlocked device** | everything that device can do, in every conversation, until it is removed and conversations are burned (L-3) | — |

Metadata is deliberately out of scope: yo! does not hide who talks to whom
from the server. This is documented in `docs/src/reference/security.md`.

## 3. Findings

Severity follows impact × likelihood for a server exposed to the internet in
the recommended `registration = "token"` mode. In `open` mode, every finding
marked "registered device" is reachable by anyone.

### H-1: Resource exhaustion on the server

**Component:** `crates/yo-server/src/server.rs` (`serve`, `connection`, `send`, mailbox handlers), `mailbox.rs`.

**Description.** The server has no limits on:

- **connections per IP or per device.** Each connection holds a tokio task,
  a TLS session and up to a 2 MiB frame buffer; a pre-`Hello` connection may
  idle for 15 s, a registered one for 300 s, a subscribed one for an hour,
  and `MailboxGet` long-polls for 25 s. Nothing stops one client from
  opening thousands.
- **queued envelope volume.** `Send` is limited to 600 requests/min per
  device, 64 envelopes each, 300 KiB each — around 11 GB/min from a single
  registered device, stored on disk until the recipient acknowledges or the
  30-day TTL passes. There is no per-recipient or per-sender quota.
- **mailbox memory.** A device may open 20 mailboxes/min, each holding up to
  16 × 64 KiB for 10 minutes, so one device can pin ~200 MiB in RAM, and the
  total number of mailboxes is unbounded.
- **TLS handshake CPU** from unregistered clients (any IP can start
  handshakes; rejection happens only at `Hello`).

**Impact.** Denial of service of the whole server by one registered device
(or, in `open` mode, by anyone), including disk exhaustion that could take
the host down. No confidentiality impact.

**CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation without Limits). **OWASP:** A04 Insecure Design, A05 Security Misconfiguration.

**Remediation.**
1. Per-IP accept limiting: a token bucket per source IP for new connections
   (e.g. 10/min burst 20) and a cap on concurrent connections per IP (e.g.
   16), enforced before the TLS handshake.
2. Per-device cap on concurrent connections (e.g. 4) after `Hello`.
3. Quotas on queued ciphertext: per recipient device (e.g. 64 MiB) and per
   sender per hour (e.g. 256 MiB); reject with `RateLimited`. Lower
   `MAX_BLOB` to the largest padded payload plus Olm overhead (~272 KiB) and
   `Send` to 120/min.
4. Mailboxes: cap total live mailboxes (e.g. 2,000), lower the per-message
   cap to 16 KiB (SPAKE2 messages are 33 bytes; link payloads are a few KB),
   and rate-limit `MailboxPut`/`MailboxGet` as `MailboxOpen` is.
5. Document running the server behind an nftables/iptables connection-rate
   rule and fail2ban on `RegistrationRequired` log lines.

**Verification.** Integration tests that (a) a 5th connection from one
device is refused, (b) a sender over quota gets `RateLimited` and the
recipient's queue stays bounded, (c) mailbox creation beyond the cap fails.

### M-1: Invite mailboxes are not bound to their participants

**Component:** `crates/yo-server/src/server.rs` (`MailboxPut`, `MailboxGet`, `MailboxClose`), `mailbox.rs`.

**Description.** `MailboxOpen` and `MailboxJoin` are rate-limited and record
nothing about who called them. `MailboxPut`, `MailboxGet` and `MailboxClose`
accept any nameplate from any registered device and are not rate-limited.
Nameplates are drawn from `1..1000` while the server is quiet, so a pending
invite's number is easy to find.

A registered device that is not party to an exchange can therefore close
someone else's mailbox, read the (public) SPAKE2 messages, or inject
messages into either side. Injection gives the attacker exactly one SPAKE2
password guess, which fails with overwhelming probability and aborts the
exchange for the real participants with "the other side typed a different
code".

**Impact.** Denial of service of `yo add` and `yo link` on a shared server.
**No confidentiality impact**: SPAKE2 holds against an active attacker with
one guess, and the opener sends secrets (in `yo link`) only after the
joiner's key-confirmation tag verifies. Every failed exchange is visible to
both users.

**CWE:** CWE-862 (Missing Authorization), CWE-330 (small nameplate space).
**OWASP:** A01 Broken Access Control.

**Remediation.**
1. Record the opener's `DeviceId` at `MailboxOpen` and the joiner's at
   `MailboxJoin`. `MailboxPut` must come from the device holding `side`,
   `MailboxGet` from the device holding `side`, `MailboxClose` from either
   participant.
2. Draw nameplates from at least `10_000..100_000` (five digits is still
   easy to read aloud) and keep growing the range under load.
3. Rate-limit `MailboxPut`/`MailboxGet`/`MailboxClose` per device.

**Verification.** Tests that a third device's put/get/close on a mailbox
returns `Unauthorized` and leaves the exchange intact.

### M-2: Terminal control sequences in messages

**Component:** `crates/yo-cli/src/ui.rs` (`card`, `history_line`, `first_line`).

**Description.** Message bodies from contacts are printed to the terminal
verbatim. A body can contain C0/C1 control characters and ANSI escape
sequences. Depending on the terminal, these can move the cursor, change
colors and the window title, clear the screen, or (in some older or
misconfigured terminals) trigger answer-back responses that end up on the
command line. The contact is a trusted party, but their device may be
compromised, and this is the one place untrusted bytes reach the user's
terminal.

**Impact.** Spoofed or hidden message content; in the worst case, terminal
feature abuse. **CWE:** CWE-150 (Improper Neutralization of Escape Sequences),
CWE-116. **OWASP:** A03 Injection.

**Remediation.** Before printing a body (and the quoted first line), replace
every character in `U+0000–U+001F` except `\n` and `\t`, every character in
`U+007F–U+009F`, and bidirectional override characters
(`U+202A–U+202E`, `U+2066–U+2069`) with a visible placeholder such as `�`
or a caret notation. Apply the same to the body before it is handed to
`$PAGER`/stdout when piped.

**Verification.** A unit test that a body containing `\x1b[2J` and `\u{202e}`
renders without those code points.

### M-3: The fallback key is never rotated

**Component:** `crates/yo-cli/src/client.rs` (`publish_prekeys` is called with `fallback = true` only from `create_relationship`; refills pass `false`).

**Description.** Each device publishes 20 one-time keys and one fallback key
per conversation. When the one-time keys are exhausted (naturally, or
because a contact's device claims them all via `ClaimKey`, which is allowed
for anyone who knows the inbox and device id), new sessions are started
against the fallback key, which is kept indefinitely. Olm sessions that start
from a fallback key still ratchet forward, but the *session-opening* message
remains decryptable by anyone who later obtains that long-lived fallback
private key together with the device's identity key.

**Impact.** Reduced forward secrecy for the first message of new sessions
after one-time keys run out. Requires a later device compromise to exploit.
**CWE:** CWE-324 (Use of a Key Past its Expiration Date). **OWASP:** A02.

**Remediation.** On each key top-up, generate a new fallback key if the
current one is older than 7 days or was ever used, and call
`forget_fallback_key()` for the previous one after a further grace period
(vodozemac keeps the previous fallback key until forgotten, so in-flight
messages still decrypt). Record the fallback creation time in the bundle.
Also refill one-time keys proactively when `KeyCount` drops below 5 (already
done) and after every `yo read`.

### M-4: `yo link` hands over the account on the strength of the code alone

**Component:** `crates/yo-cli/src/client.rs` (`link_open`, `pake_open`), `main.rs` (`Cmd::Link`).

**Description.** `yo link` shows a code; the first device to join with it
receives every conversation's identity key and the device-sync key — the
whole account. The existing device sends them as soon as the joiner's
key-confirmation tag verifies, without showing the user which device is
joining or asking for confirmation. The code has about 31 bits of entropy
and is valid for 10 minutes, the same strength as a contact invite, but the
consequence of misuse is far larger.

**Impact.** If a link code is seen by someone else within its window (e.g.
pasted into the wrong chat, shoulder-surfed) and they join first, they get a
full copy of the account. The real new device then fails to link, which is
noticeable but after the fact. **CWE:** CWE-287 (Improper Authentication),
CWE-654 (Reliance on a Single Factor). **OWASP:** A04 Insecure Design, A07.

**Remediation.**
1. The joiner already sends a `LinkHello { device }` before the opener
   sends secrets. Show that device id on the existing device and require an
   interactive `y/N` before `pake_open` sends its payload (`--yes` for
   scripts). Show the same id on the new device so the user can compare.
2. Use a longer code for linking (4 words, ~41 bits) and a shorter window
   (5 minutes).
3. Print a safety warning with the code ("anyone with this code gets a copy
   of your account for the next 5 minutes").

### M-5: Registration-token attempts are not rate-limited

**Component:** `crates/yo-server/src/server.rs` (`hello`), `db.rs` (`use_token`).

**Description.** An unregistered device may send `Hello { token }` on every
new connection with no per-IP or per-device limit; each attempt performs a
database write. Tokens are 128 bits of OS randomness in base32, so guessing
is infeasible, but the path is unthrottled. Separately, `use_token` consumes
the token *before* `register` runs, so a database error at that moment burns
the token.

**Impact.** Load amplification (a database write per unauthenticated
request) rather than account compromise. **CWE:** CWE-307 (Improper
Restriction of Excessive Authentication Attempts). **OWASP:** A07.

**Remediation.** Rate-limit failed registration attempts per source IP (e.g.
5/min) and consume the token in the same transaction as the registration
insert. Log failed attempts with the source IP so fail2ban can act on them.

### L-1: Device lists may name devices that never joined

**Component:** `crates/yo-server/src/server.rs` (`put_list`).

**Description.** A device list is accepted if it is signed by the inbox's
identity key and the caller is in the old or new list. The entries themselves
are not checked against registered devices, and a listed device never
consents. A key holder can therefore list any device id, after which `Send`
to that inbox queues envelopes for a device that has no relationship with
it. The victim's client discards them (no matching inbox) but they occupy
server storage and bump the unread counter (see L-6).

**Impact.** Nuisance and storage use; no confidentiality impact. **CWE:** CWE-863.

**Remediation.** Require every listed device to be registered. Optionally
require that a device appears in an inbox list only after that device itself
has sent a `PutDeviceList` or a signed `JoinInbox` for it — the client
already structures joins this way (`join_inbox` runs on the joining device).

### L-2: Serialized database access stalls all connections

**Component:** `crates/yo-server/src/server.rs` (`Mutex<Db>`), `db.rs`.

**Description.** One SQLite connection behind a `std::sync::Mutex` is used
from every tokio task. A slow query (e.g. `expire` on a large table, or a
large `fetch`) blocks every other request and the runtime thread holding
the lock.

**Impact.** Latency spikes and easier denial of service under load.

**Remediation.** Move database calls to `tokio::task::spawn_blocking` with a
small connection pool (r2d2/deadpool-sqlite), or at least a dedicated
blocking thread with a channel. Keep WAL mode (already on) for readers.

### L-3: Removed devices keep the conversation keys

**Component:** `crates/yo-cli/src/client.rs` (`remove_device`); documented in `docs/src/client/devices.md`.

**Description.** Every device holds the secret identity key of every
conversation. `yo devices remove` takes a device out of the signed lists so
nobody encrypts to it, but the removed device still has the keys needed to
sign a new device list or a burn, if it is unlocked and still has a valid
TLS key. The docs tell users to burn sensitive conversations after removing
a compromised device.

**Impact.** A compromised, unlocked device can keep acting in existing
conversations until they are burned. **CWE:** CWE-613 (Insufficient Session
Expiration) by analogy.

**Remediation.** Server side: on removal, also delete the device's
registration so its TLS identity is refused, and let the client call this.
Client side (larger change): rotate each conversation's identity key on
device removal by running a signed "re-key" handshake with the contact, so
the old key becomes worthless. Until then, keep the documentation prominent
and have `yo devices remove` print the burn advice (it already does).

### L-4: Message draft written to disk in the clear

**Component:** `crates/yo-cli/src/main.rs` (`edit_message`).

**Description.** Composing in `$EDITOR` writes `compose.txt` (mode 0600)
into the data directory, overwrites it with zeros and deletes it. On SSDs,
copy-on-write and journaling filesystems the overwrite does not reliably
destroy the old blocks; editors also create their own swap/backup files.

**Impact.** Plaintext of outgoing messages may be recoverable from disk by
someone with physical access. **CWE:** CWE-312.

**Remediation.** Create the draft under `$XDG_RUNTIME_DIR` (tmpfs) when
available, pass editor hints that disable swap/backup where known (e.g.
`vim -n -i NONE`), and document the residual risk.

### L-5: Sender-controlled timestamps

**Component:** `crates/yo-cli/src/payload.rs` (`Payload.sent_at`), `ui.rs`.

**Description.** The "2m ago" shown next to a message is the sender's claim.
A contact (or their compromised device) can backdate or postdate messages.
The receive time is stored (`received_at`) but not shown.

**Impact.** Misleading display; no cryptographic consequence.

**Remediation.** Show `received_at`, or show `sent_at` but flag it when it
differs from `received_at` by more than a few minutes.

### L-6: Undecryptable envelopes count as unread

**Component:** `crates/yo-store/src/spool.rs` (`incoming_count`), daemon.

**Description.** The unread counter adds every spooled envelope that is not
from one of the user's own devices, including junk that will later be
dropped (from L-1, or from a contact's broken session).

**Impact.** A false `yo!(N)` in the prompt until `yo read` runs. Annoyance.

**Remediation.** Count only envelopes whose inbox id matches a known
relationship (the daemon can keep the list of inbox ids in a small
unencrypted index, since inbox ids are already known to the server), and
subtract envelopes that fail to decrypt immediately.

### L-7: Service installers don't escape paths

**Component:** `crates/yo-cli/src/service.rs`.

**Description.** The systemd unit, launchd plist and Task Scheduler command
embed the executable path and `YO_HOME` without escaping. A path containing
quotes, newlines or XML metacharacters produces a malformed or altered
service definition. Only the user's own environment reaches this code, so
the only victim is the user.

**Impact.** Self-inflicted misconfiguration. **CWE:** CWE-116.

**Remediation.** Escape values per format (systemd quoting, XML escaping,
PowerShell single-quote doubling for `YO_HOME` as is already done for the
executable), or refuse to install when the path contains such characters.

### I-1: Informational

- **`DeleteInbox` is replayable for 24 hours.** Burning is idempotent and
  terminal, so a replay has no effect. A nonce would make this strictly
  single-use.
- **Server pin rotation.** A pinned key can't be rotated without every client
  editing `config.toml`. Consider supporting a signed "next pin" announcement
  or a list of accepted pins in the client config before this is needed.
- **Agent nuisance requests.** Any process running as the same user can
  send `Unlock` with a wrong key (subsequent commands fail with "wrong
  passphrase" until `yo unlock`) or `Shutdown`. This is inherent to
  same-user IPC and matches ssh-agent's model.
- **`YO_PASSPHRASE`** is visible to other processes of the same user via
  `/proc`. Documented as script-only.
- **Windows named pipe** uses the default ACL. Documented.
- **Dependencies.** `cargo audit` reports no known vulnerabilities. One
  advisory, RUSTSEC-2023-0089 (`atomic-polyfill` is unmaintained), concerns a
  crate that is only compiled for targets yo! does not support (it does not
  appear in the Linux, Windows or macOS dependency trees).
- **`unsafe`.** None in yo!'s own code. Memory safety relies on Rust and on
  `ring` (C/assembly, widely reviewed) for TLS primitives.

## 4. Business-logic review by feature

| Feature | What was checked | Result |
|---|---|---|
| **Registration (`yo init`)** | Device identity = TLS key hash, computed by the server from the handshake; tokens single-use; failed setups leave no half state; retry reuses the registered device | OK. Token attempts unthrottled (M-5). |
| **Invite (`yo add`)** | Fresh identity key per contact; SPAKE2 with purpose-separated identities so an `add` code can't be used for `link`; key confirmation before payloads; one join per mailbox; wrong code aborts visibly on both sides; the pending contact is discarded on failure | OK. Mailbox participants unbound (M-1). |
| **Device lists** | Signed by the inbox's key; inbox id commits to that key; version must increase (server) and never decrease (client); entries bind Olm keys to the TLS key hash; server can't add, swap or roll back | OK. Entries not checked against registered devices (L-1). |
| **Sending** | Encrypted separately for every device of the contact and every other device of mine; claimed one-time keys verified against the device's signing key; ratchet state saved before send; conflicts retried; `Burned` handled | OK. Fallback key unrotated (M-3). |
| **Receiving** | Only payloads from devices in the *signed* lists are accepted; the sender key is authenticated by Olm's 3DH, not by the claimed field; replays rejected by the ratchet; out-of-order delivery handled; dedup by HMAC tag | OK. Output unsanitized (M-2); sender timestamps (L-5). |
| **Reply** | Reply targets by uuid within the same relationship; a reply to a yo! notice is refused | OK. |
| **Device sync** | Sync events accepted only on the self relationship and only from devices in my own signed list; contact secrets travel only inside the self relationship | OK. |
| **Link (`yo link`)** | Secrets sealed under the PAKE key; sent only after the joiner's confirmation verifies; new device creates its own Olm keys per conversation | OK cryptographically. No user confirmation (M-4). |
| **Remove device** | Removed from every inbox list; server drops its keys and queue | OK. Keys not rotated (L-3). |
| **Burn** | Burn notice signed with the conversation's own key and verified against the pinned key, so it can't be forged or replayed into another conversation; server deletion signed; local crypto-shred deletes the only copy of the storage key, then `VACUUM` with `secure_delete`; other conversations untouched (tested); offline `--local`; requires typed confirmation | OK. |
| **Passphrase & agent** | Argon2id 64 MiB/3; wrong passphrase detected by a canary; agent socket 0600 in a user-only runtime dir with peer-uid check; sliding expiry; key zeroized on lock | OK. Same-user nuisance (I-1). |
| **Daemon & spool** | Needs no passphrase; envelopes stay end-to-end encrypted on disk; acks only after fsync; reconnect with backoff | OK. Unread miscount (L-6). |
| **Prompt snippet** | Reads one file with builtins; no process spawn; the file holds only a number; `--sync` runs `yo sync --quiet`, which never prompts | OK. |
| **Local storage** | Every sensitive column sealed with AEAD bound to its row id; names, bodies, timestamps and keys never in the clear (tested by scanning files); message numbers never reused; no WAL remnants | OK. Draft file (L-4). |

## 5. OWASP Top 10 (2021) and CWE Top 25 coverage

| OWASP | Assessment |
|---|---|
| A01 Broken Access Control | Fetch/Ack scoped to the authenticated device; device lists require the owning key; mailboxes **not** scoped (M-1); list entries unchecked (L-1) |
| A02 Cryptographic Failures | Modern, audited primitives; AEAD with associated data; domain-separated signatures; Argon2id; zeroization. Fallback key rotation missing (M-3) |
| A03 Injection | No dynamic SQL (all parameterized, verified by grep); no shell execution on the server; client runs only the user's own `$EDITOR`; terminal escape filtering missing (M-2); service-file escaping (L-7) |
| A04 Insecure Design | Resource limits missing (H-1); link confirmation missing (M-4) |
| A05 Security Misconfiguration | Token registration by default; `open` mode documented as risky; hardened systemd unit in docs; `yo init` warns when no pin is given |
| A06 Vulnerable and Outdated Components | `cargo audit` clean; one unmaintained crate on unsupported targets only; CI runs the audit |
| A07 Identification and Authentication Failures | Devices authenticated by mTLS key possession; people authenticated by pinned per-conversation keys; token attempts unthrottled (M-5) |
| A08 Software and Data Integrity Failures | Signed device lists with anti-rollback; AEAD on everything at rest; `Cargo.lock` committed; CI uses pinned actions by major version (consider SHA pinning) |
| A09 Security Logging and Monitoring Failures | Logs contain no message data; no abuse counters or alerting (add with H-1/M-5 fixes) |
| A10 Server-Side Request Forgery | Not applicable; the server makes no outbound requests |

| CWE Top 25 item | Status |
|---|---|
| CWE-787/125/416 memory safety | Rust, no `unsafe` in yo!; C only in `ring`/SQLite (bundled, current) |
| CWE-79 XSS | N/A (no web UI) |
| CWE-89 SQL injection | None found |
| CWE-78 OS command injection | None; the server never spawns processes |
| CWE-20 input validation | Frames bounded (2 MiB), postcard decoding fuzz-tested, names validated, sizes checked |
| CWE-400/770 resource consumption | **H-1** |
| CWE-862/863 authorization | **M-1**, L-1 |
| CWE-306 missing authentication | None: every request after `Hello` requires a registered mTLS identity |
| CWE-287/307 authentication weaknesses | M-4, M-5 |
| CWE-798 hard-coded credentials | None |
| CWE-311/312 cleartext storage/transmission | TLS 1.3 only; device TLS key stored in the clear by design (documented); draft file (L-4) |
| CWE-116/150 output encoding | **M-2**, L-7 |
| CWE-330 weak randomness | OS CSPRNG via `getrandom` everywhere; nameplate space small (M-1) |
| CWE-362 race conditions | Atomic writes with unique temp names; per-store lock file |
| CWE-502 deserialization | postcard with bounded lengths; no code execution paths |

## 6. Privacy assurance

**Who can read a message?** Only a device holding an Olm session for it:
the recipient's devices in the recipient inbox's signed list, and the
sender's other devices in the sender inbox's signed list. Both lists are
signed by per-conversation keys that each side pinned during the SPAKE2
exchange. The server stores and relays only Olm ciphertext inside TLS.
Local copies are sealed under a per-conversation storage key that exists only
inside a record sealed under the passphrase-derived key.

**Who can modify a message?** Nobody in transit or at rest: Olm authenticates
every message to the sender's identity key, the client accepts a sender only
if that key is in the signed list, and local rows are AEAD-sealed and bound to
their ids. The server (or a network attacker) can only drop, delay, reorder
or duplicate; duplicates are rejected by the ratchet and the HMAC tag.

**Who can impersonate a participant?** Only a holder of the conversation's
identity key *and* a device in its signed list, i.e. one of that person's own
devices. A compromised unlocked device is the realistic path (L-3), and burn
is the remedy.

**What leaks anyway?** Metadata to the server (who-to-whom, when, padded
sizes, IP addresses), and local counts/read-flags to someone with the disk.
Both are documented.

## 7. Remediation plan

Effort is a rough estimate for one developer familiar with the code.
Each item lists the test that proves it fixed.

### Phase 1: before internet exposure

| # | Finding | Work | Effort | Verification |
|---|---|---|---|---|
| 1.1 | H-1 | Per-IP accept token bucket + concurrent-connection cap before TLS; per-device connection cap after `Hello` | 1 day | Test: 5th connection from one device refused; 17th from one IP refused |
| 1.2 | H-1 | Queue quotas per recipient device and per sender/hour; `MAX_BLOB` 272 KiB; `Send` 120/min | ½ day | Test: over-quota `Send` returns `RateLimited`; recipient queue bounded |
| 1.3 | H-1 | Mailbox caps: 2,000 live, 16 KiB/message, rate-limit put/get/close | ½ day | Test: cap reached → `RateLimited` |
| 1.4 | M-1 | Bind opener/joiner device ids; authorize put/get/close; nameplates ≥ 10,000 | ½ day | Test: third device's put/get/close → `Unauthorized`; exchange completes |
| 1.5 | M-2 | Sanitize control and bidi characters in displayed bodies | ½ day | Unit test with escape and bidi sequences |
| 1.6 | Ops | Docs: nftables rate rule, fail2ban filter, log fields for abuse | ½ day | Docs walkthrough |

### Phase 2: next release

| # | Finding | Work | Effort | Verification |
|---|---|---|---|---|
| 2.1 | M-3 | Fallback key rotation with grace period; record creation time | 1 day | Test: after rotation, a session opened with the old fallback within the grace period still decrypts; after it, fails |
| 2.2 | M-4 | Confirmation prompt on `yo link` showing the joining device id; 4-word code; 5-minute window | ½ day | e2e test with `--yes`; manual UX check |
| 2.3 | M-5 | Per-IP throttle on failed `Hello`; consume token atomically with registration | ½ day | Test: 6th bad token in a minute → `RateLimited`; failed insert leaves token usable |
| 2.4 | L-1 | Require listed devices to be registered | ½ day | Test: list with unknown device → `BadRequest` |
| 2.5 | L-2 | Database on a blocking pool | 1 day | Load test: a slow query doesn't block `Ping` |
| 2.6 | L-6 | Unread counter ignores envelopes for unknown inboxes | ½ day | Test: junk envelope doesn't change `unread` |

### Phase 3: hardening and design improvements

| # | Finding | Work | Effort |
|---|---|---|---|
| 3.1 | L-3 | Server-side deregistration on device removal; later, conversation re-keying | 1 day / 3 days |
| 3.2 | L-4 | Drafts in `$XDG_RUNTIME_DIR`; editor swap/backup hints | ½ day |
| 3.3 | L-5 | Show/flag receive time | ½ day |
| 3.4 | L-7 | Escape values in service files | ½ day |
| 3.5 | I-1 | Nonce in `DeleteInbox`; multiple accepted pins for rotation; SHA-pin GitHub Actions | 1 day |
| 3.6 | — | Add abuse metrics (connections, rejected requests, queue sizes) to `yo-server stats` and logs | ½ day |
| 3.7 | — | Commission an independent audit of the protocol and the server once Phases 1–2 are done | external |

## 8. Residual risks after remediation

- Metadata exposure to the server operator (by design; mitigate with Tor/VPN
  and self-hosting).
- A compromised, unlocked device compromises its owner's conversations until
  they are burned or re-keyed.
- A modified client can ignore burn requests, as with any messenger.
- Dependence on the correctness of `vodozemac`, `rustls`, `ring` and
  `spake2`, all widely used but outside this review.

---

*This document is part of the yo! repository. When a finding is fixed, mark
it in the table above with the commit and add an entry to `CHANGELOG.md`.*
