# Wire protocol

For contributors and the curious. Source: `crates/yo-proto`.

## Transport

- TCP, default port 7443, TLS 1.3 only, ALPN `yo/1`.
- Both sides present Ed25519 certificates. The server accepts any
  well-formed client certificate; the device is identified by
  `DeviceId = first 16 bytes of SHA-256(SubjectPublicKeyInfo)`.
- Frames: 4-byte big-endian length + [postcard](https://postcard.jamesmunns.com)
  encoding, max 2 MiB.
- Strict request → response. After `Subscribe`, the server may also push
  `Event::Envelope` frames, so clients read `ServerFrame::{Response, Event}`.

## Requests

| Request | Purpose |
|---|---|
| `Hello { version, token }` | First frame; registers new devices (token if required). → `Hello { version, device }` |
| `PutDeviceList(SignedDeviceList)` | Create an inbox or replace its device list. The server checks the signature, `inbox == H(rik)`, that the version increases, and that the caller is in the old or new list. |
| `GetDeviceList { inbox }` | → `DeviceList(Option<…>)`, or `Burned` |
| `PublishKeys { inbox, one_time, fallback }` | Upload signed one-time keys (caller must be a member). |
| `KeyCount { inbox }` | Remaining one-time keys for the caller. |
| `ClaimKey { inbox, device }` | Take one one-time key (or the fallback key). |
| `Send { inbox, envelopes[] }` | Each envelope is `{device, blob}` and must target a device in the inbox's list. |
| `Fetch` / `Ack { ids }` | Download / delete queued envelopes. |
| `Subscribe` | Push new envelopes on this connection. |
| `DeleteInbox { inbox, ts, rik, sig }` | Burn: signed by the inbox's RIK. |
| `MailboxOpen` / `MailboxJoin` / `MailboxPut` / `MailboxGet` / `MailboxClose` | Invite rendezvous (single joiner, long-poll get, 10-minute TTL). |
| `Ping` | Keep-alive. |

Errors come back as `Response::Error { code, message }` with `code` one of
`BadRequest, RegistrationRequired, Unauthorized, NotFound, Burned, Conflict,
RateLimited, VersionMismatch, Internal`.

## Signed structures

All signatures are Ed25519 over a domain-separated byte string:

| Structure | Signed bytes | Key |
|---|---|---|
| Device list | `"yo/device-list/v1" ‖ postcard(DeviceList{inbox, version, devices})` | RIK |
| One-time key | `"yo/prekey/v1" ‖ inbox ‖ curve25519 ‖ fallback` | device's Olm Ed25519 |
| Delete inbox | `"yo/delete-inbox/v1" ‖ inbox ‖ ts(be64)` | RIK |
| Burn notice (inside E2E payload) | `"yo/burn/v1" ‖ inbox ‖ ts(be64)` | RIK |

## Envelope contents

`blob` = postcard `{ sender: curve25519, kind, body }`, where `kind`/`body`
are an Olm message (pre-key or normal). The decrypted plaintext is
`pad(postcard(Payload))`:

```rust
struct Payload { uuid: [u8; 16], sent_at: u64, body: Body }
enum Body {
    Text { text: String, reply_to: Option<[u8; 16]> },
    Burn { inbox, ts, sig },
    Sync(SyncEvent),          // ContactAdded | Renamed — own devices only
}
```

A send encrypts separately for every device in the contact's inbox, plus
every *other* device in the sender's own inbox for that conversation (the
sent-copies). The server marks an envelope `from_member` when the sender is
in the target inbox, which is how a client tells its own copies apart for the
unread count.

## Invite (SPAKE2) flow

```text
opener                         server mailbox                    joiner
MailboxOpen → n
code = n-w1-w2-w3  (shown to the user, typed by the joiner)
Put(Opener,0: spake_A) ───────▶                    ◀─────── MailboxJoin(n)   (only once)
                                                   ◀─────── Get(0) → spake_A
                               ◀─────── Put(Joiner,0: spake_B)
                               ◀─────── Put(Joiner,1: confirm_J ‖ seal_J(payload_J))
Get(0), Get(1); check confirm_J
Put(Opener,1: confirm_O ‖ seal_O(payload_O)) ─▶   ─────────▶ Get(1); check confirm_O
                                                            MailboxClose
```

SPAKE2 uses identity `yo/add/v1` or `yo/link/v1`, so a code for one purpose
can't be used for the other. Keys come from HKDF-SHA-256 over the SPAKE2
secret: separate confirmation and sealing keys per side. The opener sends
its payload (which for `yo link` contains secrets) only after checking the
joiner's confirmation.
