//! `yo-server` command-line definitions (shared with the docs-coverage test).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// yo! relay server — stores and forwards end-to-end encrypted messages.
#[derive(Parser)]
#[command(name = "yo-server", version = Box::leak(crate::status::version_string().into_boxed_str()) as &'static str, about)]
pub struct Cli {
    /// Data directory (server.toml, certificate, database).
    #[arg(long, short, env = "YO_SERVER_DIR", global = true)]
    pub dir: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Create server.toml and a self-signed certificate.
    Init {
        /// Host name or IP address clients will connect to.
        #[arg(long)]
        host: String,
        /// TCP port to listen on.
        #[arg(long, default_value_t = yo_proto::DEFAULT_PORT)]
        port: u16,
        /// Let any device register (default: registration tokens required).
        #[arg(long)]
        open: bool,
        /// Use an existing CA-issued certificate chain (PEM) instead of a
        /// self-signed one. Clients then need no pin.
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// Private key for --cert (PEM).
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// Overwrite an existing configuration.
        #[arg(long)]
        force: bool,
    },
    /// Run the server.
    Run,
    /// Print the command clients use to connect (`yo init ...`).
    Info,
    /// Show database statistics.
    Stats,
    /// Manage registration tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Manage which devices may administer the server from their client.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Make a registered device an administrator (id or its first characters,
    /// as shown by `yo status` on that device).
    Grant { device: String },
    /// Take administrator rights away from a device.
    Revoke { device: String },
    /// List registered devices and which are administrators.
    List,
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Create a token that lets new devices register.
    Create {
        /// How many devices may register with this token.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Free-form note to remember who it is for.
        #[arg(long, default_value = "")]
        note: String,
        /// The device that registers with this token becomes an administrator
        /// and can mint further tokens from its own client (`yo admin token`).
        #[arg(long)]
        admin: bool,
    },
    /// List unused tokens.
    List,
    /// Delete a token.
    Revoke { token: String },
}
