# Quick start

This walks through the whole thing on one machine: a server and two people,
alice and bob. On real deployments the server runs somewhere reachable from
the Internet and each person runs the client on their own computer.

## 1. Build

```sh
git clone https://github.com/jsprada/yo && cd yo
cargo build --release
# binaries: target/release/yo and target/release/yo-server
```

## 2. Start a server

```sh
yo-server --dir ./srv init --host localhost
yo-server --dir ./srv token create --uses 2      # prints a registration token
yo-server --dir ./srv run
```

`init` prints the exact `yo init …` command clients need, including the
server's certificate **pin**.

## 3. Set up two clients

In two terminals (`YO_HOME` keeps each person's files separate on one
machine; you don't need it normally):

```sh
# terminal A                                   # terminal B
export YO_HOME=/tmp/alice                      export YO_HOME=/tmp/bob
yo init --server localhost:7443 \              yo init --server localhost:7443 \
  --pin sha256:… --token …                       --pin sha256:… --token …
```

Each asks for a passphrase that encrypts everything stored on that device.

## 4. Exchange keys

```sh
# alice                                        # bob
yo add bob
#   → shows 7-crossbow-marble-tundra
#     and waits                                yo add alice 7-crossbow-marble-tundra
✔ bob added                                    ✔ alice added
```

## 5. Talk

```sh
yo bob "hey bob!"                              yo read
                                               yo reply 1 "hey alice"
yo read
```

## 6. Prompt indicator

```sh
yo daemon install            # notifier + passphrase cache, starts at login
yo prompt bash >> ~/.bashrc  # or zsh / fish / powershell
```

Open a new shell: your prompt now shows `yo!(N)` when messages are waiting.
