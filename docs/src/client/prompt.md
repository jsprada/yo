# Prompt indicator

Add a little `yo!(3)` to your shell prompt when messages are waiting:

```text
yo!(3) johnny@laptop ~/src $
```

## Setup

`yo prompt <shell>` prints a snippet with the right file path for this
device already filled in. Append it to your shell's startup file:

| Shell | Command |
|---|---|
| bash | `yo prompt bash >> ~/.bashrc` |
| zsh | `yo prompt zsh >> ~/.zshrc` |
| fish | `yo prompt fish > ~/.config/fish/conf.d/yo.fish` |
| PowerShell | `yo prompt powershell >> $PROFILE` |

Then open a new terminal (or `source` the file).

The indicator needs something to keep the unread count current. Pick one:

1. **The daemon (recommended):** `yo daemon install`. Updates within a
   second of a message arriving. See [Daemon](daemon.md).
2. **No daemon:** add `--sync` (`yo prompt bash --sync`). The snippet then
   starts a background `yo sync --quiet` at most once a minute. If your store
   is locked, messages are only downloaded (still encrypted) and counted;
   they're decrypted when you run `yo read`.

## How it works

The snippet reads one small file, the unread counter, using shell builtins
only (`read`, `$(<file)`), so it doesn't start any process or touch the
network. Your prompt stays instant. The file holds a number and nothing else.

The bash version, for reference:

```bash
# >>> yo! unread indicator >>>  (paste into ~/.bashrc)
__yo_prompt() {
  local n=0
  [[ -r '/home/you/.local/state/yo/unread' ]] && read -r n < '/home/you/.local/state/yo/unread'
  [[ $n =~ ^[0-9]+$ ]] || n=0
  if (( n > 0 )); then __YO=$'\001\e[1;33m\002'"yo!($n)"$'\001\e[0m\002 '; else __YO=; fi
}
PROMPT_COMMAND="__yo_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
PS1='${__YO}'"$PS1"
# <<< yo! unread indicator <<<
```

The `\001`/`\002` bytes tell readline that the color codes take no space,
so line editing keeps working.

## Customizing

- **Placement:** the snippet prefixes your existing prompt. To put it
  elsewhere, remove the `PS1=…`/`PROMPT=…` line and use `${__YO}` wherever you
  like in your own prompt.
- **Color/text:** edit the `__YO=` line. For example, to show an envelope:
  `__YO="✉ $n "`.
- **fish:** the snippet defines `fish_right_prompt`, which puts the indicator
  on the right. If you already have a right prompt, merge the body into yours.
- **Starship / oh-my-posh:** use a custom command module that runs
  `cat <path-to-unread>` (the path is in the printed snippet), with a
  condition of "output > 0".
