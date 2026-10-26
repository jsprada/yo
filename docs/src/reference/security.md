# Security model

This page explains what yo! protects, how, and where its limits are.

> **Status:** yo! is new software and has not had an independent security
> audit. Its end-to-end encryption uses `vodozemac`, which *has* been audited
> (by Least Authority, 2022). Treat yo! itself accordingly.

## Goals

1. Only the people in a conversation can read it, not the server operator,
   the hosting company, or anyone on the network.
2. Messages are encrypted in transit, on the server and on your devices.
3. Each conversation is cryptographically independent of every other one.
4. Either person can destroy a conversation.
5. Exchanging keys is easy enough that people actually do it right.

## Building blocks

| Purpose | Algorithm | Library |
|---|---|---|
| Transport | TLS 1.3 only, mutual auth, Ed25519 certificates | `rustls` (ring) |
| End-to-end messages | Olm: 3DH handshake + Double Ratchet (AES-256-CBC + HMAC-SHA-256) | `vodozemac` 0.11 |
| Identity / signatures | Ed25519 | `ed25519-dalek` |
| Key exchange from a code | SPAKE2 (Ed25519 group) + HKDF-SHA-256 + HMAC key confirmation | `spake2` |
| Passphrase → key | Argon2id, 64 MiB, 3 passes | `argon2` |
| Encryption at rest | XChaCha20-Poly1305, random 192-bit nonces | `chacha20poly1305` |

yo! uses Olm's standard (Matrix-compatible) configuration, whose message MAC
is truncated to 8 bytes.

## Keys

```text
Per device
  device TLS key (Ed25519) ······ authenticates the device to the server; decrypts nothing

Per person, per device
  passphrase ──Argon2id──▶ KEK ──wraps──▶ DK (data key, random 256-bit)

Per conversation ("relationship") — fresh for every contact
  RIK  relationship identity key (Ed25519)   pinned by the contact; signs device lists & burns
  RSK  relationship storage key (256-bit)     encrypts this conversation's rows on disk
  Olm account per device + sessions            end-to-end encryption
  inbox id = SHA-256("yo/inbox/v1" ‖ RIK public)   address on the server
```

Your own devices are joined by a private "device sync" relationship with its
own RIK. It carries contact additions, renames and burns between your
devices.

### Why a key per contact?

- **Isolation.** Compromising or deleting the keys of one conversation
  tells an attacker nothing about another. Even your devices' Olm identity
  keys are different in every conversation.
- **Destroyable.** Burning deletes the RIK, RSK and Olm state of one
  conversation and nothing else.
- **Less linkable.** Contacts can't correlate you by key: alice and carol
  see unrelated public keys for you. (The *server* can still link your
  inboxes. See metadata below.)

## Trust: who is who?

- **Contacts.** During `yo add`, the two clients run SPAKE2 with the invite
  code as the password and swap their brand-new RIK public keys, sealed with
  the resulting key. Each side then pins the other's RIK. An attacker
  (including the server) who doesn't know the code gets one guess, with odds
  of about 1 in 2³¹ for three words from the 1296-word EFF list. A failed
  guess aborts the exchange visibly on both sides.
- **Safety words** (`yo verify`) are derived from both RIK public keys, so
  you can re-check out of band at any time.
- **Key rotation.** A conversation's RIK can be replaced at any time
  (`yo rekey`): the announcement is signed by the old, pinned key *and* the
  new one, so the contact re-pins only a key the previous holder vouched for
  and that provably exists. The old inbox is retired; messages already
  queued there still arrive. Your other devices get the new secret over
  device sync; the device-sync key itself rotates the same way, which also
  rotates the key that authorizes deregistering your devices.
- **Devices.** Each inbox has a **device list** signed by its RIK, with a
  version number. Clients accept a list only if it's signed by the pinned key
  and its version isn't lower than one they've already seen (no rollback).
  Each entry binds the device's Olm keys to its TLS key hash. So the server
  can't add a device to your conversation, swap keys, or replay an old list.
  At worst it can refuse service.
- **One-time keys** are signed by the device's Olm signing key and checked
  before a session is started.
- **Incoming messages** are accepted only from devices in the signed list,
  as proven by successful Olm decryption with a session bound to that
  device's key.
- **The server** is authenticated by its pinned public-key hash (or the web
  PKI if it has a CA certificate). This protects metadata and availability.
  Message confidentiality doesn't depend on it. A client can trust more than
  one pin at a time so a self-signed certificate can be rotated without
  locking anyone out (see [Server setup](../server/setup.md#3-certificate-pin-or-ca)).

## Administration and the status page

Two conveniences were added after the initial design; both were built to
add no new way in:

- **Administrators** are registered devices with a flag on their server
  record. Admin requests (`yo admin …`) ride the same mutual-TLS connection
  as every other request, so the credential is the device's own TLS key;
  there is no password and no web interface. The flag grants exactly one
  power — admitting devices by minting registration tokens — and leaves with
  the registration if the device is removed. An administrator cannot read or
  alter messages, join conversations, or make other administrators (only the
  operator can, on the server). Minting is rate-limited and logged by device
  id; tokens minted from a client never grant admin.
- **The status page** (`yo-status`) is a separate, read-only HTTPS service
  running as its own user. It learns the server's state from a local,
  group-only Unix socket that answers one JSON line and reads nothing; page
  views are served from a once-a-minute cache and never touch the server. It
  serves `GET` only, carries no scripts, and gets its certificate from Let's
  Encrypt over TLS-ALPN on 443, so no extra port opens.

## In transit

Client ↔ server is TLS 1.3 with mutual authentication; TLS 1.2 and earlier
are refused. Inside it, every message is end-to-end encrypted, so even a
broken or malicious TLS endpoint sees only Olm ciphertext.

Before encryption, plaintext is padded to the next of these sizes: 256 B,
1 KiB, 4 KiB, 16 KiB, 64 KiB or 256 KiB. The server learns the bucket, not
the exact length.

## At rest on the server

The server stores Olm ciphertext, public keys and signed device lists, all
useless for reading messages. Envelopes are deleted when the recipient
acknowledges them (or after 30 days). Invite mailboxes exist only in memory.

## At rest on your device

`yo.db` columns:

| Table | Plaintext columns | Sealed column (XChaCha20-Poly1305) |
|---|---|---|
| `relationships` | `id` | `bundle` (nickname, RIK, RSK, pinned key, device lists) under **DK**, and `olm` (Olm account + sessions) under the conversation's **RSK** |
| `messages` | `id`, `rel_id`, `read` flag, `tag` | `blob` (body, timestamps, direction, reply-to, uuid) under the conversation's **RSK** |
| `canary` | — | a known value under DK, to detect a wrong key |

- Associated data binds every ciphertext to its row (`rel:<id>`, `olm:<id>`,
  `msg:<id>:<rel>`), so rows can't be swapped or moved between
  conversations without detection.
- `tag` is `HMAC-SHA-256(DK, rel id ‖ message uuid)`, used to drop duplicate
  deliveries without storing the uuid in the clear.
- Contact names, bodies, timestamps and keys never touch the disk unencrypted.
  A test greps the raw database files after a full run to check this.
- SQLite runs with `secure_delete = ON` and a rollback journal (no WAL
  files left behind). Burning `VACUUM`s the file.
- Memory holding keys and message bodies is wiped (`zeroize`) when it's
  freed, as far as Rust and the libraries allow.

What remains visible to someone with your disk but not your passphrase: how
many conversations and messages you have and which are read, the server
address, the unread count, and envelope files waiting in the spool (which are
end-to-end ciphertext).

## Metadata: what the server can see

Being honest about this matters. The server **can** see:

- the IP address of each device, and when it connects;
- that a device belongs to certain inboxes (all its inboxes arrive over the
  same TLS identity), and so how many conversations a device is part of;
- which device sends to which inbox, when, and the padded size;
- when a conversation is burned;
- which devices are administrators, and when one mints or revokes a token.

It can't see names, message contents, or which real person owns a device,
except what IP addresses and timing reveal. yo! doesn't hide metadata the
way Signal's sealed sender or mixnets do. If you need that, use Tor or a VPN
in front of yo!, and run your own server.

## Forward secrecy and recovery

Olm's Double Ratchet gives forward secrecy (a stolen device can't decrypt
messages from before its keys were rotated) and post-compromise recovery
(sessions heal once a compromised attacker loses access). Burning adds
deliberate destruction on top. The Olm fallback key — used to open a session
when a device's one-time keys are exhausted — is rotated by the client (after
a week, or sooner once keys run low), with the previous key kept for one more
period so in-flight session setups still decrypt.

## Known limitations

- **Stolen device.** Every one of your devices holds your conversations'
  RIKs. `yo devices remove` deregisters the device on the server (cutting off
  its access, including any session it still has open), removes it from every
  device list, and **rotates every conversation key**, so the copies it holds
  stop working. The window that remains is between the theft and your
  running the removal: a thief who can unlock the device could use it, or
  even rotate keys first, until then. See [Devices](../client/devices.md).
- **Modified clients** can ignore burn requests. No messenger can prevent
  this.
- **The agent** hands the key to any process running as your user while
  unlocked. On Windows the named pipe uses the default ACL, which lets other
  local accounts open it read-only. That isn't enough to send a request, but
  it's weaker than the Unix setup.
- **Denial of service.** A malicious server can drop, delay, reorder or
  refuse messages, or hide devices from device lists. It can't read or forge
  them, and replayed messages are rejected by the ratchet. Against abusive
  *clients*, the server enforces per-IP, per-device and per-recipient limits
  (see [Server setup](../server/setup.md#7-firewall-and-abuse-protection)).
- **Terminal output.** Message text is a contact's input. Control characters,
  C1 controls and Unicode direction overrides are replaced with `�` before
  anything is printed, so a message cannot drive your terminal.
- **Invite codes** sent through another app are exposed to that app until
  used. A code is single-use and expires in 10 minutes.
- **No history on new devices**, by design.
