//! `yo daemon`: keeps a connection to the server, writes incoming envelopes
//! to the spool, maintains the unread counter for the prompt, and serves the
//! passphrase agent. It never needs the passphrase to collect messages.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::bail;
use tokio::sync::Notify;
use yo_proto::msg::Request;
use yo_store::{ClientConfig, Paths, spool};

use crate::agent::{self, AgentState};
use crate::client::download_to_spool;
use crate::net::Conn;

pub async fn run(paths: Paths) -> anyhow::Result<()> {
    if agent::status(&paths).await.is_some() {
        bail!("the yo daemon is already running");
    }
    let cfg = ClientConfig::load(&paths)?;
    std::fs::write(paths.daemon_pid(), std::process::id().to_string())?;

    let state = Arc::new(Mutex::new(AgentState::default()));
    let shutdown = Arc::new(Notify::new());

    let mut agent_task = tokio::spawn(agent::serve(paths.clone(), state.clone(), shutdown.clone()));
    log("daemon started");

    #[cfg(unix)]
    {
        // Survive the terminal that started us closing.
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut hup) = signal(SignalKind::hangup()) {
            tokio::spawn(async move { while hup.recv().await.is_some() {} });
        }
    }

    let mut backoff = Duration::from_secs(1);
    loop {
        let res = tokio::select! {
            r = relay(&paths, &cfg, &state) => r,
            _ = shutdown.notified() => break,
            _ = tokio::signal::ctrl_c() => break,
            r = &mut agent_task => {
                let why = match r {
                    Ok(Ok(())) => "stopped".to_string(),
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => e.to_string(),
                };
                log(&format!("agent failed: {why}"));
                let _ = std::fs::remove_file(paths.daemon_pid());
                bail!("the passphrase agent could not run: {why}");
            }
        };
        {
            let mut s = state.lock().expect("agent state");
            s.connected = false;
            if let Err(e) = &res {
                log(&format!("connection lost: {e:#}"));
                s.last_error = Some(format!("{e:#}"));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.notified() => break,
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
        if res.is_ok() {
            backoff = Duration::from_secs(1);
        }
    }
    let _ = std::fs::remove_file(paths.daemon_pid());
    #[cfg(unix)]
    let _ = std::fs::remove_file(paths.agent_socket());
    log("daemon stopped");
    Ok(())
}

fn log(msg: &str) {
    eprintln!("{} {msg}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
}

/// One connected session: subscribe, drain the backlog, then wait for pushes.
async fn relay(paths: &Paths, cfg: &ClientConfig, state: &Arc<Mutex<AgentState>>) -> anyhow::Result<()> {
    let mut conn = Conn::connect(paths, cfg, None).await?;
    conn.call(Request::Subscribe).await?;
    download_to_spool(&mut conn, paths).await?;
    spool::refresh_unread(paths, None)?;
    {
        let mut s = state.lock().expect("agent state");
        s.connected = true;
        s.last_error = None;
    }
    log(&format!("connected to {}", cfg.server));
    let mut ping = tokio::time::interval(Duration::from_secs(60));
    ping.tick().await;
    loop {
        tokio::select! {
            env = conn.next_event() => {
                let env = env?;
                spool::write(paths, &env)?;
                conn.call(Request::Ack { ids: vec![env.id] }).await?;
                spool::refresh_unread(paths, None)?;
            }
            _ = ping.tick() => {
                tokio::time::timeout(Duration::from_secs(20), conn.call(Request::Ping)).await??;
            }
        }
    }
}

/// Start `yo daemon run` in the background, detached from this terminal.
pub fn spawn_background(paths: &Paths) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(paths.daemon_log())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["daemon", "run"]).stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log);
    if let Some(home) = std::env::var_os("YO_HOME") {
        cmd.env("YO_HOME", home);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()?;
    Ok(())
}

/// Wait (briefly) until a freshly started daemon answers.
pub async fn wait_until_up(paths: &Paths) -> bool {
    for _ in 0..30 {
        if agent::status(paths).await.is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}
