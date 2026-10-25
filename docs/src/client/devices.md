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

Removing takes the device out of the signed device list of every
conversation, so nobody encrypts new messages to it. The server deletes its
one-time keys and anything queued for it. You can't remove the device you're
using. Do it from another one.

### If a device is lost or stolen

Its data is encrypted with that device's passphrase. If the passphrase is
strong and unknown to the thief, removing the device is enough.

If you think the thief **knows the passphrase**, remember that every device
holds the keys for your conversations (that's what lets it sign device lists
and read messages). After `yo devices remove`, also
[burn](burn.md) any conversation that matters and re-add those contacts.
That creates fresh keys the old device never had.
