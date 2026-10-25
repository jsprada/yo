# Install & set up a client

## 1. Get the `yo` binary

From source (Rust 1.85 or newer, on Linux, macOS or Windows; the client
is built and tested on all three in CI):

```sh
git clone https://github.com/jsprada/yo && cd yo
cargo install --path crates/yo-cli      # installs `yo` into ~/.cargo/bin
```

Check it works:

```sh
yo --version
```

## 2. Get an invitation from the server operator

You need three things, usually sent as a single command:

- the server address, e.g. `yo.example.com:7443`
- the server **pin**, e.g. `sha256:uavoahcy…` (not needed if the server uses a
  CA certificate)
- a registration **token** (if the server requires one)

> The pin is what guarantees you're talking to the real server. Get it from
> the operator over a channel you trust.

## 3. `yo init`

```sh
yo init --server yo.example.com:7443 --pin sha256:uavoahcy… --token vil2sobn…
```

yo! asks you to choose a **passphrase**. It encrypts everything yo! stores on
this device: your keys, contacts and messages. Pick something long. Three or
four random words is good. If you forget it, the data on this device can't
be recovered.

`yo init`:

1. creates a TLS client certificate for this device (this is how the
   server recognizes the device; it can't decrypt anything);
2. registers the device with the server (using the token);
3. creates your encrypted local store;
4. creates the private "device sync" conversation between your own devices.

You can also pass the token as `YO_TOKEN=… yo init …`.

If `yo init` is interrupted or fails (a typo in the address, say), run it
again. Setup only counts as finished once `config.toml` is written, and a
retry reuses an already-registered device certificate, so it doesn't use up
another token.

### Already use yo! on another device?

Don't run a plain `yo init`. Link the new device to your account instead, so
it gets your contacts. See [Multiple devices](devices.md):

```sh
# on the old device
yo link
# on the new device (the command is printed by `yo link`)
yo init --server … --pin … --link 71502-twirl-ozone-rust
```

## 4. Recommended extras

```sh
yo daemon install           # background notifier + passphrase cache (starts at login)
yo prompt bash >> ~/.bashrc # unread indicator (also zsh, fish, powershell)
```

See [Daemon & passphrase agent](daemon.md) and [Prompt indicator](prompt.md).

## Where things are stored

| | Linux | macOS | Windows |
|---|---|---|---|
| settings (`config.toml`) | `~/.config/yo/` | `~/Library/Application Support/yo/` | `%APPDATA%\yo\config\` |
| keys, messages | `~/.local/share/yo/` | `~/Library/Application Support/yo/` | `%APPDATA%\yo\data\` |
| unread counter, daemon log | `~/.local/state/yo/` | `~/Library/Application Support/yo/` | `%LOCALAPPDATA%\yo\data\` |

Set `YO_HOME=/some/dir` to keep everything in one directory instead (useful
for testing, or for separate identities on one machine). Full list in
[Files & settings](../reference/files.md).

## Changing your passphrase

```sh
yo passwd
```

This re-wraps the data key with the new passphrase. It's instant and doesn't
touch your messages.

## Removing yo! from a device

1. On another of your devices: `yo devices remove <id>` (so nobody keeps
   encrypting to this device).
2. On this device: `yo daemon uninstall`, then delete the directories above.
