use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Parser;
use yo_server::cli::{Cli, Cmd, TokenCmd};
use yo_server::db::Db;
use yo_server::{Config, Registration, Server};

fn default_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "yo-server")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("yo-server-data"))
}

fn open_db(dir: &Path) -> anyhow::Result<Db> {
    Db::open(&dir.join("yo-server.db")).context("opening database")
}

fn print_client_command(dir: &Path, cfg: &Config) -> anyhow::Result<()> {
    let host = &cfg.public_host;
    let port = cfg.port();
    let pin = yo_server::pin(dir, cfg)?;
    println!("Clients connect with:\n");
    let mut cmd = format!("  yo init --server {host}:{port}");
    if let Some(p) = pin {
        cmd.push_str(&format!(" --pin {p}"));
    }
    if cfg.registration == Registration::Token {
        cmd.push_str(" --token <TOKEN>");
    }
    println!("{cmd}\n");
    if cfg.registration == Registration::Token {
        println!("Create a token per person with:  yo-server token create");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let dir = cli.dir.unwrap_or_else(default_dir);

    match cli.cmd {
        Cmd::Init { host, port, open, cert, key, force } => {
            std::fs::create_dir_all(&dir)?;
            if dir.join("server.toml").exists() && !force {
                bail!("{} already exists (use --force to overwrite)", dir.join("server.toml").display());
            }
            let mut cfg = Config::new(host.clone(), port);
            if open {
                cfg.registration = Registration::Open;
            }
            match (cert, key) {
                (Some(c), Some(k)) => {
                    cfg.cert = std::fs::canonicalize(c)?;
                    cfg.key = std::fs::canonicalize(k)?;
                    cfg.pinned = false;
                }
                _ => {
                    let mut names = vec![host.clone()];
                    if host != "localhost" {
                        names.push("localhost".into());
                    }
                    let (cert_pem, key_pem) = yo_proto::tls::generate_cert(names)?;
                    std::fs::write(dir.join("server.crt"), cert_pem)?;
                    write_private(&dir.join("server.key"), key_pem.as_bytes())?;
                }
            }
            cfg.save(&dir)?;
            open_db(&dir)?;
            println!("Created {}\n", dir.join("server.toml").display());
            print_client_command(&dir, &cfg)?;
            println!("\nStart the server with:  yo-server --dir {} run", dir.display());
        }
        Cmd::Run => {
            tracing_subscriber::fmt()
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
                )
                .init();
            let cfg = Config::load(&dir)?;
            let tls = yo_server::tls_config(&dir, &cfg)?;
            let db = yo_server::DbPool::open(&dir.join("yo-server.db"), cfg.limits.db_connections)
                .context("opening database")?;
            let listener =
                tokio::net::TcpListener::bind(&cfg.listen).await.with_context(|| format!("binding {}", cfg.listen))?;
            tracing::info!("yo-server listening on {} (registration: {:?})", cfg.listen, cfg.registration);
            if let Some(p) = yo_server::pin(&dir, &cfg)? {
                tracing::info!("certificate pin: {p}");
            }
            Server::new(db, &cfg).serve(listener, tls).await?;
        }
        Cmd::Info => {
            let cfg = Config::load(&dir)?;
            print_client_command(&dir, &cfg)?;
        }
        Cmd::Stats => {
            for (k, v) in open_db(&dir)?.stats()? {
                println!("{k:>26}: {v}");
            }
        }
        Cmd::Token { cmd } => {
            let db = open_db(&dir)?;
            match cmd {
                TokenCmd::Create { uses, note } => {
                    let token = yo_proto::b32(&random16());
                    db.create_token(&token, uses, &note, yo_proto::now())?;
                    println!("{token}");
                    eprintln!("(valid for {uses} device registration(s))");
                }
                TokenCmd::List => {
                    for (t, uses, _, note) in db.list_tokens()? {
                        println!("{t}  uses left: {uses}  {note}");
                    }
                }
                TokenCmd::Revoke { token } => {
                    if !db.revoke_token(&token)? {
                        bail!("no such token");
                    }
                    println!("revoked");
                }
            }
        }
    }
    Ok(())
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("os rng");
    b
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}
