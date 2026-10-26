//! Command-line definitions (shared with the docs-coverage test).

use clap::{Parser, Subcommand};

use crate::prompt::Shell;

pub const AFTER_HELP: &str = "\
Send a message:
  yo <name> <message>        e.g.  yo alice \"lunch at noon?\"
  yo <name>                  compose in $EDITOR (or pipe text on stdin)

First steps:
  yo init --server HOST:PORT --pin sha256:...   set up this device
  yo add bob                                    show a code for bob
  yo add alice 48213-crossbow-marble-tundra         use the code alice gave you
  yo prompt bash                                prompt indicator snippet

Docs: https://github.com/jsprada/yo (docs/ folder)";

/// yo! — private, end-to-end encrypted messages from your terminal.
#[derive(Parser)]
#[command(name = "yo", version, about, after_help = AFTER_HELP, args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Set up yo! on this device (or join your account with --link).
    Init {
        /// Server address, HOST:PORT.
        #[arg(long)]
        server: String,
        /// Server certificate pin printed by `yo-server init` (sha256:...).
        #[arg(long)]
        pin: Option<String>,
        /// Registration token from the server operator.
        #[arg(long, env = "YO_TOKEN")]
        token: Option<String>,
        /// Link this device to your existing account with a code from `yo link`.
        #[arg(long, value_name = "CODE")]
        link: Option<String>,
    },
    /// Add a contact: without CODE shows a code to give them; with CODE uses theirs.
    Add {
        /// Your name for this contact (only you see it).
        name: String,
        /// The invite code they gave you, e.g. 48213-crossbow-marble-tundra.
        code: Vec<String>,
        /// Also show the code as a QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Show new messages.
    Read,
    /// Reply to message number N.
    Reply {
        /// The message number shown by `yo read` (e.g. 12 or #12).
        number: String,
        /// Your reply (omit to use $EDITOR or stdin).
        message: Vec<String>,
    },
    /// Show the conversation with a contact.
    History {
        name: String,
        /// How many messages to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        count: usize,
    },
    /// List your contacts.
    Contacts,
    /// Rename a contact (on all your devices).
    Rename { old: String, new: String },
    /// Permanently destroy a conversation, on both sides.
    Burn {
        name: String,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// Only destroy your local copy (use when the server is unreachable).
        #[arg(long)]
        local: bool,
    },
    /// Show safety words to compare with a contact.
    Verify { name: String },
    /// Show a code to set up yo! on another device of yours.
    Link {
        /// Also show the code as a QR code.
        #[arg(long)]
        qr: bool,
        /// Don't ask before sending your account to the device that joins.
        #[arg(long)]
        yes: bool,
    },
    /// Rotate a conversation's keys (e.g. after a device was lost).
    Rekey {
        /// The contact whose conversation to re-key.
        name: Option<String>,
        /// Every conversation, plus your device-sync key.
        #[arg(long)]
        all: bool,
    },
    /// List (or remove) your devices.
    Devices {
        #[command(subcommand)]
        cmd: Option<DevicesCmd>,
    },
    /// Cache your passphrase in the agent (starts the daemon if needed).
    Unlock {
        /// Minutes to stay unlocked after last use.
        #[arg(long = "for", value_name = "MINUTES")]
        minutes: Option<u64>,
    },
    /// Forget the cached passphrase now.
    Lock,
    /// Change your passphrase.
    Passwd,
    /// Fetch new messages now.
    Sync {
        /// Never prompt or print (for the prompt snippet's background refresh).
        #[arg(long, short)]
        quiet: bool,
    },
    /// Background notifier + passphrase agent.
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
    /// Print a shell snippet that shows yo!(N) in your prompt.
    Prompt {
        #[arg(value_enum)]
        shell: Shell,
        /// Also refresh in the background from the prompt (if you don't run the daemon).
        #[arg(long)]
        sync: bool,
    },
    /// Show connection, lock and unread status.
    Status,
    /// Administer the server from this device (if the operator made it an admin).
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    #[command(external_subcommand)]
    Send(Vec<String>),
}

#[derive(Subcommand)]
pub enum DevicesCmd {
    /// Remove a lost or old device from all your conversations.
    Remove {
        /// Device id (or its first characters) from `yo devices`.
        id: String,
        /// Don't rotate conversation keys afterwards (they are rotated by
        /// default so the removed device's copies become useless).
        #[arg(long)]
        no_rekey: bool,
    },
}

#[derive(Subcommand)]
pub enum DaemonCmd {
    /// Run in the foreground.
    Run,
    /// Start in the background.
    Start,
    /// Stop the running daemon.
    Stop,
    /// Show whether it is running.
    Status,
    /// Start automatically at login (systemd / launchd / Task Scheduler).
    Install,
    /// Remove the login service.
    Uninstall,
}

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Mint a registration token and print the `yo init` line to send.
    Token {
        /// How many devices may register with it.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// A note to remember who it is for.
        #[arg(long, default_value = "")]
        note: String,
    },
    /// List unspent tokens.
    Tokens,
    /// Delete a token.
    Revoke { token: String },
    /// Server version, uptime, counts and abuse counters.
    Status,
}
