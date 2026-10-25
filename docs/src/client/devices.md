# Multiple devices

You can use yo! from several computers: a laptop, a desktop, a server you SSH
into. Messages reach all of them, and what you send from one shows up on the
others.

## Link a new device

On a device **already set up**:

```console
$ yo link
 ── link a new device ───────────────────
 On the new device run:

     yo init --server yo.example.com:7443 --pin sha256:… --link 71502-twirl-ozone-rust

     71502-twirl-ozone-rust

 Waiting… the code works once and expires in 10 minutes.
```

On the **new** device, run the printed command (add `--token …` if the
server needs one for new devices):

```console
$ yo init --server yo.example.com:7443 --pin sha256:… --link 71502-twirl-ozone-rust
 This device is eh67hc3n. Your other device will ask you to approve it.
```

The existing device then asks you to confirm, showing the same id:

```console
 Device eh67hc3n wants to link. It should show the same id. Send it your account? [y/N] y
✔ linked device eh67hc3n
```

Check the two ids match before you answer `y`. This is the moment that
authorizes handing over your account, so a code seen by someone else is not
enough on its own — they would also have to be approved here. The new device
then finishes and picks its own passphrase (passphrases are per device). Use
`yo link --yes` to skip the prompt (for scripts).

Because a link code carries your whole account, it has four words instead of
three and lives for five minutes instead of ten.

What happens:

1. The two devices run the same SPAKE2 exchange used for
   [adding contacts](contacts.md), with the code as the password.
2. After you approve the new device's id, the old device sends, encrypted
   with the exchanged key, the identity keys of your device-sync conversation
   and of each contact conversation.
3. The new device makes its **own** encryption keys for each conversation,
   adds itself to each conversation's signed device list, and publishes its
   one-time keys.

Your contacts' clients see the new device the next time they send to you,
and verify it's genuine: device lists must be signed with the key they
pinned when you added each other.

> Message **history is not copied**. A new device starts with your contacts
> but an empty inbox.

## Staying in sync

These changes reach your other devices automatically:

| Change on one device | Effect on the others |
|---|---|
| `yo add` a contact | contact appears ("added contact X (from another device)") |
| `yo rename` | nickname updates |
| messages you send | appear in their history as sent by "you" |
| `yo burn` | conversation is destroyed there too |

## List and remove devices

```console
$ yo devices
 Your devices:
   rnthy3ui  added Mar 3 14:05 (this device)
   eh67hc3n  added just now
 Remove a lost device with: yo devices remove <id>

$ yo devices remove eh67
✔ removed device eh67hc3n from all conversations
```

Removing a device does three things:

1. **Takes it out of every signed device list**, so nobody encrypts new
   messages to it.
2. **Deregisters it on the server**, cutting off its network access: the
   server forgets its registration, keys and queued messages, drops any
   connection it still has open, and (on a token server) it would need a
   fresh token to reconnect. This works because each device, at setup, tells
   the server which key may later remove it — your account's own identity
   key, which only your devices hold.
3. **Rotates every conversation key** (`yo rekey --all` under the hood).
   The removed device still holds a copy of each conversation's identity
   key; after the rotation those copies are worthless. Your contacts pick the
   new keys up automatically on their next sync, with no interruption, and
   your other devices receive the new secrets over device sync.

You can't remove the device you're using; do it from another one.
`--no-rekey` skips step 3, which is only sensible when you are retiring a
device you still control and want to save a few seconds.

### Rotating keys by hand

```sh
yo rekey bob      # one conversation
yo rekey --all    # every conversation, plus your device-sync key
```

Rotation is cheap and invisible to the other side (they see "bob rotated
their keys" in `yo read`'s notices and nothing else changes), so it's fine to
do after anything that makes you uneasy — a laptop that was briefly out of
your hands, say.

### If a device is lost or stolen

Its data is encrypted with that device's passphrase. If the passphrase is
strong and unknown to the thief, removing the device is enough: its data
stays encrypted and `yo devices remove` deregisters it, so it can't even
collect ciphertext from the server any more.

If you think the thief **knows the passphrase**, the key rotation that
`yo devices remove` performs is what protects you: every device holds the
keys for your conversations (that's what lets it sign device lists and read
messages), so a thief who can unlock the device has those keys — until they
are rotated, which the removal does. Do it **as soon as you notice**: until
then the thief's copy is as good as yours, and whoever rotates first wins.
If you want belt and braces, [burn](burn.md) the conversations that matter
most and re-add those contacts as well.
