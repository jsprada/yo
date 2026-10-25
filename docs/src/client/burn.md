# Burning a conversation

`yo burn <name>` permanently destroys **one** conversation, for both people,
on all their devices. Your other conversations are not affected in any way.

```console
$ yo burn alice
💥 This permanently destroys your conversation with alice:
   • every message and key for it on this device and your other devices
   • alice's devices are told to destroy their copy as well
   (yo! on alice's side complies automatically; a modified client could keep a copy)
 Type alice to confirm: alice
✔ burned — alice's devices and yours were told (3 devices)
```

On alice's side, the next sync shows:

```text
 ┌ #31 yo! · just now
 │ 💥 bob burned your conversation. Its messages and keys are gone from this device.
 └
```

Either person can burn. Afterwards the conversation is gone. To talk again,
run `yo add` for a brand-new conversation with brand-new keys.

## What exactly happens

On the device where you run it:

1. A **burn notice** is sent, end-to-end encrypted, to every device of the
   contact *and* every other device of yours. The notice is signed with
   *this conversation's* identity key, so it can't be forged, and can't be
   replayed against a different conversation.
2. Your inbox for the conversation is deleted on the server (a request
   signed with the same key). The server forgets its device list and one-time
   keys and refuses any new messages to it. It keeps only a small "burned"
   marker for 30 days.
3. **Crypto-shredding:** the conversation's local record is deleted. That
   record is the only copy of its storage key, identity key and encryption
   sessions, so every message row encrypted with that storage key becomes
   permanently undecryptable. The rows are deleted too, and the database is
   `VACUUM`ed with SQLite's `secure_delete` on, so freed pages are
   overwritten.

On each receiving device (theirs and yours), yo! checks the notice's
signature, forwards it to that person's other devices, deletes their inbox
too, and shreds its local copy the same way.

A device that's offline gets the notice when it reconnects. Notices already
queued on the server stay deliverable after the inbox is deleted.

## Guarantees and limits

**Guaranteed:**

- Your copy is destroyed on this device immediately.
- No new messages can be sent in this conversation, in either direction.
- Because of forward secrecy and the deleted keys, someone who recorded the
  encrypted traffic can't decrypt it later from any device that has burned.
- Other conversations, including other conversations with the *same*
  person's devices, are untouched. They use unrelated keys.

**Not possible to guarantee** (for any messenger):

- yo! can't force a **modified client** on the other side to delete its
  copy, and can't erase what someone already copied, screenshotted or
  remembered.
- **Backups** of your data directory taken before the burn, plus your
  passphrase, still contain the conversation. Don't back up the yo! data
  directory if burn matters to you.

## Offline burn

If the server can't be reached, `yo burn` refuses so the other side isn't
left out. To destroy only your local copy right away, without notifying
anyone:

```sh
yo burn alice --local
```

## Scripting

`--yes` skips the confirmation prompt: `yo burn alice --yes`.
