//! Copy-paste shell prompt snippets for the unread indicator.
//!
//! Every snippet only *reads a small file* (`unread`) with shell builtins, so
//! it adds no process spawn and no network round-trip to your prompt. The
//! daemon keeps that file current.

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

/// Quote a path for POSIX shells.
fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

pub fn snippet(shell: Shell, unread: &Path, with_sync: bool) -> String {
    match shell {
        Shell::Bash => {
            let f = sh_quote(unread);
            let sync = if with_sync {
                "\n  # No daemon? Refresh in the background at most once a minute.\n  \
                 local now=${EPOCHSECONDS:-$(date +%s)}\n  if (( now - ${__YO_LAST:-0} >= 60 )); then __YO_LAST=$now; (yo sync --quiet >/dev/null 2>&1 &); fi"
            } else {
                ""
            };
            format!(
                r#"# >>> yo! unread indicator >>>  (paste into ~/.bashrc)
__yo_prompt() {{
  local n=0
  [[ -r {f} ]] && read -r n < {f}
  [[ $n =~ ^[0-9]+$ ]] || n=0{sync}
  if (( n > 0 )); then __YO=$'\001\e[1;33m\002'"yo!($n)"$'\001\e[0m\002 '; else __YO=; fi
}}
PROMPT_COMMAND="__yo_prompt${{PROMPT_COMMAND:+; $PROMPT_COMMAND}}"
PS1='${{__YO}}'"$PS1"
# <<< yo! unread indicator <<<
"#
            )
        }
        Shell::Zsh => {
            let f = sh_quote(unread);
            let sync = if with_sync {
                "\n  if (( EPOCHSECONDS - ${__YO_LAST:-0} >= 60 )); then __YO_LAST=$EPOCHSECONDS; (yo sync --quiet >/dev/null 2>&1 &); fi"
            } else {
                ""
            };
            let load = if with_sync { "zmodload zsh/datetime\n" } else { "" };
            format!(
                r#"# >>> yo! unread indicator >>>  (paste into ~/.zshrc)
{load}__yo_prompt() {{
  local n=0
  [[ -r {f} ]] && n=$(<{f})
  [[ $n == <-> ]] || n=0{sync}
  if (( n > 0 )); then __YO="%B%F{{yellow}}yo!($n)%f%b "; else __YO=; fi
}}
autoload -Uz add-zsh-hook
add-zsh-hook precmd __yo_prompt
setopt PROMPT_SUBST
PROMPT='${{__YO}}'"$PROMPT"
# <<< yo! unread indicator <<<
"#
            )
        }
        Shell::Fish => {
            let f = unread.display().to_string().replace('\'', "\\'");
            let sync = if with_sync {
                "\n    set -l now (date +%s)\n    if test (math $now - (set -q __yo_last; and echo $__yo_last; or echo 0)) -ge 60\n        set -g __yo_last $now\n        yo sync --quiet >/dev/null 2>&1 &\n        disown 2>/dev/null\n    end"
            } else {
                ""
            };
            format!(
                r#"# >>> yo! unread indicator >>>  (save as ~/.config/fish/conf.d/yo.fish)
# Shows yo!(N) on the right side of the prompt.
function fish_right_prompt{sync}
    set -l f '{f}'
    if test -r $f
        read -l n < $f
        if string match -qr '^[0-9]+$' -- $n; and test $n -gt 0
            set_color -o yellow; echo -n "yo!($n)"; set_color normal
        end
    end
end
# <<< yo! unread indicator <<<
"#
            )
        }
        Shell::Powershell => {
            let f = unread.display().to_string().replace('\'', "''");
            format!(
                r#"# >>> yo! unread indicator >>>  (paste into your $PROFILE)
if (-not $global:__yoOriginalPrompt) {{ $global:__yoOriginalPrompt = $function:prompt }}
function global:prompt {{
    $n = 0
    $f = '{f}'
    if (Test-Path -LiteralPath $f) {{ [void][int]::TryParse(([IO.File]::ReadAllText($f)).Trim(), [ref]$n) }}
    $p = & $global:__yoOriginalPrompt
    if ($n -gt 0) {{ "$([char]27)[1;33myo!($n)$([char]27)[0m " + $p }} else {{ $p }}
}}
# <<< yo! unread indicator <<<
"#
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn bash_snippet_runs() {
        // Smoke-test the bash snippet when bash is available.
        let Ok(out) = std::process::Command::new("bash").arg("--version").output() else { return };
        if !out.status.success() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let unread = dir.path().join("unread");
        std::fs::write(&unread, "3").unwrap();
        let script = format!("PS1='$ '\n{}\n__yo_prompt\nprintf '%s' \"$__YO\"", snippet(Shell::Bash, &unread, false));
        let out = std::process::Command::new("bash").arg("--norc").arg("-c").arg(&script).output().unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(s.contains("yo!(3)"), "{s:?} {}", String::from_utf8_lossy(&out.stderr));
        std::fs::write(&unread, "0").unwrap();
        let out = std::process::Command::new("bash").arg("--norc").arg("-c").arg(&script).output().unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("yo!"));
    }
}
