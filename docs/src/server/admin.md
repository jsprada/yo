# Administration from your client

Once a server runs, the one recurring chore is admitting new people: each
device needs a registration token. You don't have to SSH in for that. A device
the operator has marked as an **administrator** can mint tokens, list and
revoke them, and read the server's health, all with the ordinary `yo` client:

```console
$ yo admin token --note alice
✔ token k7xq2m5v3t4bz7wlnhgjc2ue4a (1 registration, alice)

 Send them this line, over a channel you trust:

   yo init --server yo.example.com:7443 --pin sha256:… --token k7xq2m5v3t4bz7wlnhgjc2ue4a

 They need Rust: cargo install --git https://github.com/jsprada/yo yo-cli

$ yo admin tokens
$ yo admin revoke k7xq2m5v3t4bz7wlnhgjc2ue4a
$ yo admin status
 ── yo-server 0.1.0 (33239c7) ───────────
 up since        3d 4h 12m …
 devices         5 (1 admin)
 unspent tokens  2
 …
```

## How it stays safe

- **No new surface.** Admin requests travel over the same mutual-TLS
  connection and the same bounded protocol as everything else. There is no
  password, no web form and no extra port; the credential is the admin
  device's own TLS key, the strongest identity in the system.
- **Admin means "may admit devices", nothing more.** Registration and
  conversations are separate layers: an administrator cannot read anyone's
  messages, join anyone's conversation, or see who talks to whom beyond what
  the server stores anyway. Tokens minted from a client never grant admin.
- **It's a flag on the server, not a secret on the device.** The flag lives
  on the device's registration record. If an admin device is lost,
  `yo devices remove` from another of your devices deregisters it, and the
  admin power goes with it. The operator can also revoke it directly.
- **Rate-limited and logged.** At most 10 tokens a minute per admin device;
  every mint and revoke is logged with the device id (never the token).

## Becoming an administrator

**When setting up**: create your own first token with `--admin`, and the
device you register with it is an administrator from the start:

```sh
runuser -u yo -- yo-server --dir /var/lib/yo-server token create --admin --note me
```

**For a device that's already registered**: grant it by id (shown by
`yo status` on that device; the first few characters are enough):

```sh
runuser -u yo -- yo-server --dir /var/lib/yo-server admin grant rnthy3ui
runuser -u yo -- yo-server --dir /var/lib/yo-server admin list
runuser -u yo -- yo-server --dir /var/lib/yo-server admin revoke rnthy3ui
```

Several people can be administrators; each uses their own device.

## What stays on SSH

Upgrading the server (`yo-server-update`), changing `server.toml`, and
anything that touches the machine itself. Those are deliberately not in the
protocol: driving software upgrades through the messaging channel is risk
the project doesn't need, and the weekly auto-update timer removes most of
the reason to log in at all.
