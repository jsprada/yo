# Adding contacts

Adding someone exchanges cryptographic keys between you. yo! makes that a
matter of reading out a short code.

## The invite code

One person **shows** a code, the other **types** it.

```console
$ yo add bob
 ── invite for bob ──────────────────────
 Give bob this code (read it out, or send it somewhere you trust):

     7-crossbow-marble-tundra

 They run:  yo add <your-name> 7-crossbow-marble-tundra
 Waiting… the code works once and expires in 10 minutes (Ctrl-C to cancel).
```

Bob runs:

```console
$ yo add alice 7-crossbow-marble-tundra
✔ alice added — keys exchanged and verified by the code
  safety words: dowry dandy carve flap angle sling
  Say hi:  yo alice hey!
```

and alice's terminal says `✔ bob added …` at the same moment.

- The **name** you type (`bob`, `alice`) is your private nickname for that
  person. It never leaves your devices, so bob doesn't know you call him bob.
- Both people must run their command within **10 minutes**, and they must
  be online at the same time (the code is a live rendezvous, not a message).
- Spaces, dashes and capitals don't matter: `7 Crossbow marble TUNDRA` works.
- `yo add bob --qr` also shows the code as a QR code, handy in person: bob
  scans it with his phone's camera and reads it off the screen.

### Ways to share the code

| Situation | How |
|---|---|
| Phone call | Read the code aloud. |
| In person | Show your screen, or `--qr`. |
| Chat app | Paste it. This is only as private as that app, but a code is useless once it has been used or has expired, so the window is short. |

## Why this is safe

The code is the password for **SPAKE2**, a password-authenticated key
exchange. The two clients use it to prove to each other that they know the
same code, and to encrypt the keys they swap. It goes through a temporary
mailbox on the server, but:

- The server (or anyone watching) learns nothing about the code from the
  exchange.
- Anyone who doesn't know the code gets **one guess**. A wrong code destroys
  the mailbox and both sides see an error. With about 31 bits of randomness
  in the code, a guess almost certainly fails, and it's noticed.
- What gets exchanged is a **brand-new identity key made just for this
  contact**. Your conversations with different people share no keys.

If the exchange fails you'll see:

```text
✖ the other side typed a different code — nothing was exchanged. Start again with a new code
```

Just run `yo add` again for a fresh code. If you cancel a `yo add` with
Ctrl-C, the unfinished contact shows as "… invite not finished" in
`yo contacts`, and the next `yo add` with that name replaces it.

## Safety words

```console
$ yo verify bob
 Safety words for bob:

     dowry  dandy  carve  flap  angle  sling

 Compare them with bob in person or on the phone.
 If they match, nobody is in the middle of your conversation.
```

Both of you see the same six words, derived from the two identity keys of
your conversation. You don't have to compare them, since the invite code
already authenticated the exchange. But comparing them later (say, the next
time you meet) is a good independent check.

## Listing, renaming, removing

```console
$ yo contacts
 alice                ✔ verified  since Mar 3 14:05  2 new
 bob                  ✔ verified  since 1h ago

$ yo rename bob robert      # renames on all your devices
```

To remove a contact *and* destroy the conversation on both sides, use
[`yo burn`](burn.md).

## Contact names

Names can use letters, digits, `.`, `_` and `-` (up to 32 characters). They
can't be one of yo!'s command names (`read`, `add`, `burn`, …), because
`yo <name> <message>` would be ambiguous.
