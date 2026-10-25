//! `yo-server` command-line definitions (shared with the docs-coverage test).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// yo! relay server — stores and forwards end-to-end encrypted messages.
#[derive(Parser)]
#[command(name = "yo-server", version, about)]
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
    },
    /// List unused tokens.
    List,
    /// Delete a token.
    Revoke { token: String },
}
