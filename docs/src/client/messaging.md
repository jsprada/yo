# Sending and reading messages

## Send

```sh
yo alice "lunch at noon?"
yo alice lunch at noon          # quotes are optional…
yo alice "it's raining"         # …but use them when the text has ' " ; & | * ? etc.
```

Without a message, yo! opens your editor (`$VISUAL`, then `$EDITOR`, then
`vi`, or `notepad` on Windows). Lines starting with `#` are ignored. The
draft is written to your data directory, overwritten and deleted afterwards.

```sh
yo alice                         # compose in $EDITOR
cat notes.txt | yo alice         # or pipe text in
```

The confirmation tells you how many devices received it:

```text
✔ sent to alice (2 devices)
```

That counts alice's devices plus your own other devices (which get a copy, so
your sent messages show up everywhere). `N unreachable` means a device had no
encryption keys available; it receives later messages once it comes back
online.

Messages can be up to 64,000 bytes (about 64 KB, or roughly 10,000 words).

## Read

```console
$ yo read
 yo! ── 2 new
 ┌ #12 alice · 2m ago
 │ lunch at noon?
 └ ↩ yo reply 12 …
 ┌ #13 bob · just now
 │ ↪ re #9: did you push the fix?
 │ yes, it's in
 └ ↩ yo reply 13 …
```

`yo read` fetches anything new from the server, decrypts it, shows unread
messages, and marks them read. The numbers (`#12`) are local to your device
and never reused. Notices from yo! itself (for example "bob burned your
conversation") show up here too.

If the server can't be reached, `yo read` says so and shows whatever was
already downloaded by the [daemon](daemon.md).

## Reply

```sh
yo reply 12 "yes, see you there"
yo reply '#12' sounds good       # '#' must be quoted in most shells
yo reply 12                      # compose in $EDITOR
```

A reply goes to whoever sent message #12, and their client shows what it
refers to (`↪ re #…`).

## History

```console
$ yo history alice -n 5
 ── alice ───────────────────────────────
 #10   you Mon 09:12
       did you get the tickets?
 #11   alice Mon 09:15
       yes!
 #12   alice 2m ago
       lunch at noon?
```

`-n N` sets how many messages to show (default 20). Showing a conversation
marks it read.

## Sync without reading

```sh
yo sync          # fetch and decrypt, print the unread count
yo sync --quiet  # used by the prompt snippet; never prompts or prints
```

## Typos

`yo raed` doesn't silently send a message to a contact called "raed":

```text
✖ no contact named 'raed'. Did you mean `yo read`?
```
