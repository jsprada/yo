//! Install `yo daemon` to start at login:
//! systemd user unit (Linux), launchd agent (macOS), logon task (Windows).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, bail};

fn exe() -> anyhow::Result<PathBuf> {
    Ok(std::env::current_exe()?.canonicalize()?)
}

/// A value going into a service file. Rejects control characters outright
/// (they have no legitimate place in a path or `YO_HOME`) so no amount of
/// escaping has to account for newlines (SECURITY_REVIEW.md L-7).
fn checked(s: &str, what: &str) -> anyhow::Result<String> {
    if s.chars().any(|c| c.is_control()) {
        bail!("{what} contains control characters; refusing to write a service file");
    }
    Ok(s.to_string())
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Quote a value for a systemd unit (double-quoted, backslash-escaped).
#[cfg(target_os = "linux")]
fn systemd_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let out = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    fn unit_path() -> anyhow::Result<PathBuf> {
        let base = directories::BaseDirs::new().context("no home directory")?;
        Ok(base.config_dir().join("systemd/user/yo-daemon.service"))
    }

    pub fn install() -> anyhow::Result<String> {
        let path = unit_path()?;
        std::fs::create_dir_all(path.parent().expect("has parent"))?;
        let exe = checked(&exe()?.display().to_string(), "executable path")?;
        let env = match std::env::var("YO_HOME") {
            Ok(h) => format!("Environment={}\n", systemd_quote(&format!("YO_HOME={}", checked(&h, "YO_HOME")?))),
            Err(_) => String::new(),
        };
        let unit = format!(
            "[Unit]\nDescription=yo! message notifier and passphrase agent\nAfter=network-online.target\n\n\
             [Service]\nExecStart={} daemon run\n{env}Restart=on-failure\nRestartSec=5\n\n\
             [Install]\nWantedBy=default.target\n",
            systemd_quote(&exe)
        );
        std::fs::write(&path, unit)?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("systemctl").args(["--user", "enable", "--now", "yo-daemon.service"]))?;
        Ok(format!("installed {} and started it", path.display()))
    }

    pub fn uninstall() -> anyhow::Result<String> {
        let path = unit_path()?;
        let _ = run(Command::new("systemctl").args(["--user", "disable", "--now", "yo-daemon.service"]));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
        Ok(format!("removed {}", path.display()))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    const LABEL: &str = "com.github.yo.daemon";

    fn plist_path() -> anyhow::Result<PathBuf> {
        let base = directories::BaseDirs::new().context("no home directory")?;
        Ok(base.home_dir().join(format!("Library/LaunchAgents/{LABEL}.plist")))
    }

    pub fn install() -> anyhow::Result<String> {
        let path = plist_path()?;
        std::fs::create_dir_all(path.parent().expect("has parent"))?;
        let exe = xml_escape(&checked(&exe()?.display().to_string(), "executable path")?);
        let env = match std::env::var("YO_HOME") {
            Ok(h) => format!(
                "<key>EnvironmentVariables</key><dict><key>YO_HOME</key><string>{}</string></dict>",
                xml_escape(&checked(&h, "YO_HOME")?)
            ),
            Err(_) => String::new(),
        };
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>daemon</string><string>run</string></array>
  {env}
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict></plist>
"#
        );
        std::fs::write(&path, plist)?;
        let _ = run(Command::new("launchctl").arg("unload").arg(&path));
        run(Command::new("launchctl").arg("load").arg("-w").arg(&path))?;
        Ok(format!("installed {} and started it", path.display()))
    }

    pub fn uninstall() -> anyhow::Result<String> {
        let path = plist_path()?;
        let _ = run(Command::new("launchctl").arg("unload").arg("-w").arg(&path));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(format!("removed {}", path.display()))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

    const TASK: &str = "yo daemon";

    pub fn install() -> anyhow::Result<String> {
        let exe = checked(&exe()?.display().to_string(), "executable path")?.replace('\'', "''");
        let home = match std::env::var("YO_HOME") {
            Ok(h) => format!("$env:YO_HOME='{}'; ", checked(&h, "YO_HOME")?.replace('\'', "''")),
            Err(_) => String::new(),
        };
        let action = format!("powershell.exe -NoProfile -WindowStyle Hidden -Command \"{home}& '{exe}' daemon run\"");
        run(Command::new("schtasks")
            .args(["/Create", "/TN", TASK, "/TR", &action, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"]))?;
        let _ = run(Command::new("schtasks").args(["/Run", "/TN", TASK]));
        Ok(format!("created logon task '{TASK}' and started it"))
    }

    pub fn uninstall() -> anyhow::Result<String> {
        run(Command::new("schtasks").args(["/Delete", "/TN", TASK, "/F"]))?;
        Ok(format!("deleted logon task '{TASK}'"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    pub fn install() -> anyhow::Result<String> {
        anyhow::bail!("automatic start is not supported on this OS; run `yo daemon start` from your login script")
    }
    pub fn uninstall() -> anyhow::Result<String> {
        anyhow::bail!("not supported on this OS")
    }
}

pub use imp::{install, uninstall};
