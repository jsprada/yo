use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use futures_util::StreamExt;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use tokio::sync::RwLock;
use yo_status::{App, Config, Snapshot, Tls, poller, router, version_string};

/// yo! status page: a read-only HTTPS page showing whether the local
/// yo-server is up, its deployed version, and what yo! is.
#[derive(Parser)]
#[command(name = "yo-status", version = Box::leak(version_string().into_boxed_str()) as &'static str)]
struct Cli {
    /// Configuration file.
    #[arg(long, short, env = "YO_STATUS_CONFIG", default_value = "/etc/yo-status/config.toml")]
    config: PathBuf,
    /// Check the configuration and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    rustls::crypto::ring::default_provider().install_default().ok();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    if cli.check {
        println!("configuration ok");
        return Ok(());
    }
    let addr: SocketAddr = cfg.listen.parse().with_context(|| format!("bad listen address {}", cfg.listen))?;

    let shared = Arc::new(RwLock::new(Snapshot::starting(cfg.poll_seconds)));
    tokio::spawn(poller(cfg.clone(), shared.clone()));
    let app = router(App {
        shared,
        github: cfg.github.as_str().into(),
        server_address: cfg.server_address.as_deref().map(Into::into),
    });

    tracing::info!(
        "yo-status {} on {addr}, polling {} every {}s",
        version_string(),
        cfg.status_socket.display(),
        cfg.poll_seconds
    );
    match cfg.tls {
        Tls::None => {
            tracing::warn!("serving plain HTTP (tls.mode = \"none\"); only for testing");
            axum_server::bind(addr).serve(app.into_make_service()).await?;
        }
        Tls::Files { cert, key } => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| format!("loading {} / {}", cert.display(), key.display()))?;
            axum_server::bind_rustls(addr, tls).serve(app.into_make_service()).await?;
        }
        Tls::SelfSigned { domains } => {
            let (cert, key) = yo_proto::tls::generate_cert(domains)?;
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem(cert.into_bytes(), key.into_bytes()).await?;
            tracing::warn!("serving with a self-signed certificate; browsers will warn");
            axum_server::bind_rustls(addr, tls).serve(app.into_make_service()).await?;
        }
        Tls::Acme { domains, email, cache_dir, production } => {
            std::fs::create_dir_all(&cache_dir)?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut state = AcmeConfig::new_with_provider(domains, provider.clone())
                .contact_push(format!("mailto:{email}"))
                .cache(DirCache::new(cache_dir))
                .directory_lets_encrypt(production)
                .state();
            let acceptor = state.axum_acceptor(state.default_rustls_config_with_provider(provider));
            tokio::spawn(async move {
                while let Some(ev) = state.next().await {
                    match ev {
                        Ok(ok) => tracing::info!("acme: {ok:?}"),
                        Err(e) => tracing::error!("acme: {e:?}"),
                    }
                }
            });
            axum_server::bind(addr).acceptor(acceptor).serve(app.into_make_service()).await?;
        }
    }
    Ok(())
}
