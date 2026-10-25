# Daemon & passphrase agent

`yo daemon` is an optional background process that does two things:

1. **Notifier:** keeps a connection to the server open, receives new
   messages the moment they arrive, and updates the unread counter that the
   [prompt indicator](prompt.md) reads. It stores messages *still end-to-end
   encrypted* in a spool, so it **never needs your passphrase**.
2. **Passphrase agent:** after you unlock once, it remembers your data key
   in memory so commands don't ask for the passphrase every time.

## Start at login (recommended)

```sh
yo daemon install
```

| OS | What it installs |
|---|---|
| Linux | systemd user unit `~/.config/systemd/user/yo-daemon.service` (enabled and started) |
| macOS | launchd agent `~/Library/LaunchAgents/com.github.yo.daemon.plist` |
| Windows | Task Scheduler logon task "yo daemon" (runs hidden) |

`yo daemon uninstall` removes it.

## Manual control

```sh
yo daemon start     # start in the background now
yo daemon status    # running? connected? locked?
yo daemon stop
yo daemon run       # run in the foreground (logs to the terminal)
```

```console
$ yo daemon status
✔ running (pid 41822)
   server: connected
   store:  unlocked (12m left)
```

The background daemon logs to `daemon.log` in your state directory (see
[Files](../reference/files.md)). It reconnects automatically, backing off up
to a minute between attempts.

## Unlocking

```sh
yo unlock            # asks for your passphrase, starts the daemon if needed
yo unlock --for 120  # stay unlocked for 120 minutes after last use
yo lock              # forget the key now
```

- When you type your passphrase for any command and the daemon is running,
  the key is cached automatically for `unlock_minutes` (default **15**).
- The timer is **sliding**: each use extends it.
- `yo lock`, stopping the daemon, or the timer running out wipes the key from
  memory.
- To never cache, set `unlock_minutes = 0` in `config.toml`. `yo unlock`
  then still works, using 15 minutes when no `--for` is given.

## How the agent is protected

- **Linux/macOS:** a Unix socket in `$XDG_RUNTIME_DIR` (a per-user directory
  only you can access) or in your data directory, with mode `0600`. The
  daemon also checks that the connecting process belongs to the same user.
- **Windows:** a named pipe. Windows' default pipe permissions give full
  access only to you, SYSTEM and administrators.

Anyone who can run code as *your user* while the store is unlocked can ask
the agent for the key. That's inherent to any passphrase cache (ssh-agent
and gpg-agent work the same way). Use `yo lock` or a short `--for` on shared
machines.

## Without the daemon

Everything still works: each command asks for your passphrase (or uses
`YO_PASSPHRASE`, intended for scripts), and `yo read` fetches messages
itself. Only the prompt indicator needs either the daemon or the
`--sync` snippet.
