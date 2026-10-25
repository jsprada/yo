# Troubleshooting

Start with `yo status`, which checks the configuration, the daemon and the
network in one go.

### "the server's certificate does not match your pinned fingerprint"

Your client reached something that isn't the server it was set up with.
Either someone is intercepting the connection, or the operator regenerated
the server's certificate. **Don't work around this blindly.** Ask the
operator, through another channel, for the current pin (`yo-server info`).
If the server really was re-installed, edit `pin` in `config.toml`.

### "this server needs a registration token"

Ask the operator for `yo-server token create`, then
`yo init … --token <TOKEN>`. Each new device uses up one registration.

### "cannot reach …" / "timed out connecting"

Check the address and port, and that the server's firewall allows the port
(default 7443/tcp). `yo-server` must receive the TLS connection directly,
not behind an HTTP reverse proxy.

### "the code did not match" / "the exchange was aborted"

One of you mistyped the code, it expired (10 minutes), or someone else
tried to use it. Nothing was exchanged. Run `yo add` again for a fresh code.

### "yo! is locked. Run `yo unlock` first"

The command wasn't run in a terminal (so it couldn't ask for your
passphrase) and the agent isn't unlocked. Run `yo unlock`, or for scripts set
`YO_PASSPHRASE`.

### The prompt indicator doesn't change

- Is the daemon running? `yo daemon status`. Start it with
  `yo daemon install` (or use `yo prompt bash --sync`).
- Did you open a new shell after adding the snippet?
- `cat` the path in your snippet: it should contain a number.

### "agent socket path is too long"

Unix socket paths are limited to about 100 bytes. Use a shorter `YO_HOME`,
or make sure `XDG_RUNTIME_DIR` is set.

### "… has no devices that can receive messages right now"

Your contact's devices have no encryption keys published. This usually
happens briefly right after they set up. It fixes itself once one of their
devices comes online (`yo sync`).

### "the server says this conversation was burned"

The server refuses messages to that conversation. If your contact burned
it, your next `yo read` shows a notice and removes it. If not, run
`yo burn <name>` to remove your copy, then `yo add` again.

### Daemon logs

`daemon.log` in your state directory (see [Files](reference/files.md)), or
`journalctl --user -u yo-daemon` on Linux with `yo daemon install`.

### Starting over on a device

```sh
yo daemon uninstall
rm -rf ~/.config/yo ~/.local/share/yo ~/.local/state/yo   # Linux paths
```

From another device, `yo devices remove <id>` the old one.
