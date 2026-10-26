# Command reference

Every `yo` and `yo-server` command and option. (A test in the repository
checks this page against the real command-line definitions, so it can't fall
out of date.)

## `yo` (client)

### `yo <name> <message…>`

Send a message to the contact you named `<name>`. Words after the name are
joined with spaces. Without a message, opens `$VISUAL`/`$EDITOR`, or reads
standard input when it's piped. → [Messaging](../client/messaging.md)

### `yo`

With no arguments: banner, unread count, and a few hints.

### `yo init`

Set up yo! on this device. → [Install](../client/install.md)

| Option | |
|---|---|
| `--server HOST:PORT` | Server address (required). |
| `--pin sha256:…` | Pin of the server's certificate. Omit only for servers with a CA certificate. |
| `--token TOKEN` | Registration token (also `YO_TOKEN`). |
| `--link CODE` | Join your existing account using a code from `yo link`. → [Devices](../client/devices.md) |

### `yo add`

`yo add <name>` shows an invite code and waits. `yo add <name> <code>` uses
the code someone gave you. → [Contacts](../client/contacts.md)

| Option | |
|---|---|
| `--qr` | Also show the code as a QR code. |

### `yo read`

Fetch, decrypt and show new messages, then mark them read.

### `yo reply <number> [message…]`

Reply to message `<number>` (`12` or `#12`).

### `yo history <name>`

Show the conversation with `<name>`.

| Option | |
|---|---|
| `-n`, `--count N` | Number of messages (default 20). |

### `yo contacts`

List contacts with verification status and unread counts.

### `yo rename <old> <new>`

Rename a contact on all your devices.

### `yo verify <name>`

Show the six safety words for a conversation.

### `yo burn <name>`

Permanently destroy a conversation on both sides. → [Burn](../client/burn.md)

| Option | |
|---|---|
| `--yes` | Don't ask for confirmation. |
| `--local` | Only shred your local copy; don't contact the server. |

### `yo link`

Show a code for setting up another device of yours. The new device shows its
id and you approve it before any secret is sent. → [Devices](../client/devices.md)

| Option | |
|---|---|
| `--qr` | Also show the code as a QR code. |
| `--yes` | Don't ask before sending your account to the device that joins. |

### `yo devices`

List your devices.

### `yo devices remove <id>`

Remove a device (id or its first characters) from every conversation,
deregister it on the server, and rotate every conversation key so the
copies it holds become useless. → [Devices](../client/devices.md)

| Option | |
|---|---|
| `--no-rekey` | Skip the key rotation (not recommended after a loss). |

### `yo rekey [name]`

Rotate the identity key of one conversation (`yo rekey bob`), or of every
conversation plus your device-sync key (`yo rekey --all`). Contacts pick the
new key up on their next sync; nothing is interrupted.

| Option | |
|---|---|
| `--all` | Every conversation and the device-sync key. |

### `yo unlock`

Cache the passphrase in the agent; starts the daemon if needed.

| Option | |
|---|---|
| `--for MINUTES` | Stay unlocked this long after last use (default: `unlock_minutes`, 15). |

### `yo lock`

Wipe the cached key from the agent.

### `yo passwd`

Change your passphrase.

### `yo sync`

Fetch and decrypt new messages, print the unread count.

| Option | |
|---|---|
| `-q`, `--quiet` | Never prompt or print. If locked, only download (still encrypted) and update the counter. |

### `yo daemon run`

Run the notifier/agent in the foreground.

### `yo daemon start`

Start it in the background.

### `yo daemon stop`

Stop it (wipes the cached key).

### `yo daemon status`

Running? Connected? Locked?

### `yo daemon install`

Start it automatically at login (systemd user unit / launchd agent / logon task).

### `yo daemon uninstall`

Remove the login service.

### `yo prompt <shell>`

Print the prompt-indicator snippet. `<shell>` is `bash`, `zsh`, `fish` or
`powershell`. → [Prompt](../client/prompt.md)

| Option | |
|---|---|
| `--sync` | Make the snippet refresh in the background (for use without the daemon). |

### `yo status`

Server, pin, device id, data directory, daemon/agent state, network check,
unread count.

### `yo admin token`

Mint a registration token on the server and print the full `yo init …` line
to send to the new person. Only works on a device the operator has made an
administrator. → [Administration](../server/admin.md)

| Option | |
|---|---|
| `--uses N` | How many devices may register with it (default 1, max 100). |
| `--note TEXT` | A note to remember who it is for. |

### `yo admin tokens`

List unspent tokens.

### `yo admin revoke <token>`

Delete an unspent token.

### `yo admin status`

Server version and uptime, device/token/inbox counts, and the abuse counters.

### Global

| Option | |
|---|---|
| `-h`, `--help` | Help (also `yo help <command>`). |
| `-V`, `--version` | Version. |

### Environment variables

| Variable | |
|---|---|
| `YO_HOME` | Keep all files in this directory. |
| `YO_PASSPHRASE` | Passphrase for non-interactive use (scripts, tests). Anyone who can read your environment can read it. |
| `YO_TOKEN` | Default for `yo init --token`. |
| `VISUAL`, `EDITOR` | Editor for composing messages. |
| `NO_COLOR` | Disable colors (also disabled automatically when output isn't a terminal). |

## `yo-server`

Global option: `-d`, `--dir DIR` (also `YO_SERVER_DIR`): the data directory.
→ [Server setup](../server/setup.md)

### `yo-server init`

| Option | |
|---|---|
| `--host HOST` | Name or IP clients connect to (required). |
| `--port N` | Listen port (default 7443). |
| `--open` | Open registration (no tokens). |
| `--cert FILE` | Use a CA-issued certificate chain… |
| `--key FILE` | …and its private key. |
| `--force` | Overwrite existing configuration. |

### `yo-server run`

Run the server. Log level via `RUST_LOG` (default `info`).

### `yo-server info`

Print the `yo init …` command (with pin) for clients.

### `yo-server stats`

Counts of devices, inboxes, queued envelopes, keys.

### `yo-server token create`

| Option | |
|---|---|
| `--uses N` | Registrations allowed (default 1). |
| `--note TEXT` | A note for yourself. |
| `--admin` | The device that registers with this token becomes an administrator and can mint further tokens from its own client (`yo admin token`). Use it for your own first device. |

### `yo-server token list`

List unused tokens.

### `yo-server token revoke <token>`

Delete a token.

### `yo-server admin grant <device>`

Make a registered device an administrator (`<device>` is the id or its first
characters, as shown by `yo status` on that device).

### `yo-server admin revoke <device>`

Take administrator rights away again.

### `yo-server admin list`

Registered devices and which of them are administrators.
