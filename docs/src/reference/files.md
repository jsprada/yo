# Files & settings

## Client files

Locations are listed in [Install](../client/install.md#where-things-are-stored).
With `YO_HOME` set, they're all in that one directory.

| File | Contents | Encrypted? |
|---|---|---|
| `config.toml` | server address, pin, preferences | no (no secrets) |
| `keyfile` | Argon2id salt + parameters, data key wrapped by your passphrase | yes |
| `yo.db` | SQLite: contacts, keys, Olm sessions, messages | yes, every sensitive column |
| `device.crt`, `device.key` | this device's TLS client certificate/key (mode 0600) | no (see below) |
| `spool/*.env` | downloaded envelopes not yet decrypted | yes (end-to-end ciphertext) |
| `unread`, `unread.db` | unread counter for the prompt (a number) | no |
| `inboxes` | this device's inbox ids, one per line, so the daemon can ignore junk addressed to inboxes it doesn't have; inbox ids are already known to the server | no |
| `daemon.log`, `daemon.pid` | daemon log and process id | no |
| `yo.lock` | prevents two `yo` commands writing at once | — |
| `compose-<pid>.txt` | a message draft, only while your editor is open, then wiped; written under `$XDG_RUNTIME_DIR` (RAM) when available | no |

**Why `device.key` isn't encrypted:** the daemon must connect to the server
without knowing your passphrase. The key only proves *which device* is
connecting. It can't decrypt anything. Someone who steals it could download
(and so delete) ciphertext queued for this device, but not read it.

What's inside `yo.db`, and what's left in the clear, is described in
[Security model](security.md#at-rest-on-your-device).

## `config.toml`

```toml
server = "yo.example.com:7443"
pin = "sha256:uavoahcysxqo5liv366n7ogbm4rvbv3spee2rckftwozso2cfjbq"
extra_pins = []       # additional pins accepted during a certificate rotation
unlock_minutes = 15   # agent cache time after last use; 0 = don't cache automatically
banner = true         # show the yo! banner when running `yo` alone
```

## Agent socket

| OS | Location |
|---|---|
| Linux (and others with `XDG_RUNTIME_DIR`) | `$XDG_RUNTIME_DIR/yo-<hash>.sock` |
| macOS / no runtime dir | `<data dir>/agent.sock` |
| Windows | named pipe `\\.\pipe\yo-agent-<hash>` |

`<hash>` is derived from the data directory, so several `YO_HOME`s don't
collide.

## Server files

See [Server setup](../server/setup.md): `server.toml`, `server.crt`,
`server.key`, `yo-server.db`.
