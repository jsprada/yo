# yo!

```text
 _   _  ___   _
| | | |/ _ \ | |
| |_| | (_) ||_|
 \__, |\___/ (_)
 |___/
```

**yo!** is a small, private messenger for the command line.

```console
$ yo alice "lunch at noon?"
✔ sent to alice (2 devices)

$ yo read
 yo! ── 1 new
 ┌ #12 alice · 2m ago
 │ sure — the usual place?
 └ ↩ yo reply 12 …

$ yo reply 12 "yes, see you there"
```

- **End-to-end encrypted.** Messages are encrypted on your device and only
  decrypted on your contact's devices, using the Olm Double Ratchet (the
  protocol behind Matrix, implemented by the audited
  [`vodozemac`](https://github.com/matrix-org/vodozemac) library). The server
  relays ciphertext it cannot read.
- **Encrypted everywhere.** In transit (TLS 1.3 with mutual authentication),
  on the server (it only ever holds end-to-end ciphertext), and on your disk
  (every message and key is sealed under your passphrase).
- **A separate key for every contact.** Each conversation has its own
  identity key, its own encryption sessions, its own storage key and its own
  address on the server. Compromising or deleting one conversation leaves the
  others untouched.
- **Burn a conversation.** `yo burn alice` destroys the conversation for
  good on your devices and tells alice's devices to do the same, without
  affecting anything else.
- **Simple key exchange.** `yo add bob` shows a code like
  `7-crossbow-marble-tundra`. Read it to bob over the phone or in person; he
  types it in. Keys are exchanged with a password-authenticated key exchange
  (SPAKE2), so not even the server can intercept them.
- **A prompt indicator.** Paste a snippet into your shell config and your
  prompt shows `yo!(3)` when messages are waiting.
- **Multiple devices** per person, on Linux, macOS and Windows.

## How it fits together

```text
   your laptop                    yo-server                     alice's phone/laptop
 ┌──────────────┐  TLS 1.3 + mTLS ┌───────────────┐  TLS 1.3 + mTLS ┌──────────────┐
 │ yo (client)  │◀───────────────▶│ relay & queue │◀───────────────▶│ yo (client)  │
 │  ├ keys ─────┼─ encrypted at   │  ciphertext   │                 │              │
 │  └ messages  │  rest (Argon2id │  only, never  │                 │              │
 └──────────────┘  + XChaCha20)   │  plaintext    │                 └──────────────┘
        ▲                         └───────────────┘                        ▲
        └──────────── end-to-end encryption (Olm Double Ratchet) ─────────┘
```

The two layers do different jobs:

| Layer | Protects | Between |
|---|---|---|
| **mTLS** | the network hop; tells the server *which device* is connecting; your client pins the server's certificate | your device ↔ server |
| **End-to-end (Olm)** | the message itself — the server can't read or forge it | your device ↔ your contact's devices |

mTLS alone cannot make messages private from the server, because TLS ends
*at* the server. That's why yo! adds the end-to-end layer, and why trust
between two people comes from the keys you exchange with an invite code, not
from TLS.

## Where to go next

- Running a server for your friends? → [Server setup](server/setup.md)
- Got an invitation to a server? → [Install & set up a client](client/install.md)
- Curious how it's secured? → [Security model](reference/security.md)
