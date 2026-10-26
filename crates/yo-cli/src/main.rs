use std::io::{IsTerminal, Read, Write};

use anyhow::{Context, anyhow, bail};
use clap::Parser;
use yo_cli::cli::{AdminCmd, Cli, Cmd, DaemonCmd, DevicesCmd};
use yo_cli::client::{Client, InitOptions, RESERVED};
use yo_cli::ui;
use yo_cli::{agent, daemon, service};
use yo_crypto::Key32;
use yo_crypto::kdf::KdfParams;
use yo_store::{ClientConfig, KeyFile, Paths, StoreError, spool};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let paths = Paths::from_env();
    if let Err(e) = run(cli, paths).await {
        let msg = match e.downcast_ref::<StoreError>() {
            Some(StoreError::NotInitialized) => {
                "yo! isn't set up on this device yet. Start with:\n  yo init --server HOST:PORT --pin sha256:..."
                    .to_string()
            }
            _ => format!("{e:#}"),
        };
        ui::error(&msg);
        std::process::exit(1);
    }
}

fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

fn read_passphrase(prompt: &str) -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("YO_PASSPHRASE") {
        return Ok(p);
    }
    if !interactive() {
        bail!("yo! is locked. Run `yo unlock` first (or set YO_PASSPHRASE for scripts)");
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn new_passphrase() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("YO_PASSPHRASE") {
        return Ok(p);
    }
    println!("{}", ui::dim("Choose a passphrase. It encrypts everything yo! stores on this device."));
    loop {
        let a = rpassword::prompt_password("New passphrase: ")?;
        if a.chars().count() < 8 {
            ui::warn("use at least 8 characters (a few random words work well)");
            continue;
        }
        let b = rpassword::prompt_password("Repeat passphrase: ")?;
        if a == b {
            return Ok(a);
        }
        ui::warn("the two passphrases differ, try again");
    }
}

/// Get the data key: environment, then the agent, then an interactive prompt.
async fn data_key(paths: &Paths, cfg: &ClientConfig) -> anyhow::Result<Key32> {
    if let Ok(p) = std::env::var("YO_PASSPHRASE") {
        return Client::unlock(paths, &p);
    }
    if let Some(k) = agent::get_key(paths).await {
        return Ok(k);
    }
    let kf = KeyFile::load(&paths.keyfile())?;
    for attempt in 0..3 {
        let p = read_passphrase("Passphrase: ")?;
        match kf.unlock(&p) {
            Ok(dk) => {
                if cfg.unlock_minutes > 0 {
                    let _ = agent::unlock(paths, &dk, cfg.unlock_minutes).await;
                }
                return Ok(dk);
            }
            Err(StoreError::WrongPassphrase) if attempt < 2 => ui::warn("wrong passphrase"),
            Err(e) => return Err(e.into()),
        }
    }
    bail!("wrong passphrase")
}

async fn open(paths: &Paths) -> anyhow::Result<Client> {
    let cfg = ClientConfig::load(paths)?;
    let dk = data_key(paths, &cfg).await?;
    Client::open(paths.clone(), dk)
}

fn edit_message(paths: &Paths, to: &str) -> anyhow::Result<String> {
    if !interactive() {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s.trim_end().to_string());
    }
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| if cfg!(windows) { "notepad".into() } else { "vi".into() });
    // Prefer a RAM-backed runtime dir (tmpfs) so the plaintext draft never
    // reaches persistent storage (SECURITY_REVIEW.md L-4).
    let dir = paths.runtime_dir();
    let file = dir.join(format!("compose-{}.txt", std::process::id()));
    yo_store::write_private(&file, format!("\n# Message to {to}. Lines starting with # are ignored.\n").as_bytes())?;
    let mut parts = editor.split_whitespace();
    let prog = parts.next().unwrap_or("vi");
    let mut cmd = std::process::Command::new(prog);
    cmd.args(parts);
    // Keep vim-family editors from leaving swap/undo/backup copies behind.
    if let Some(base) = std::path::Path::new(prog).file_stem().and_then(|s| s.to_str())
        && matches!(base, "vi" | "vim" | "nvim" | "view")
    {
        cmd.args(["-n", "-i", "NONE"]);
    }
    let status = cmd.arg(&file).status();
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    // Overwrite before deleting so the draft doesn't linger on disk.
    let _ = std::fs::write(&file, vec![0u8; text.len()]);
    let _ = std::fs::remove_file(&file);
    status.with_context(|| format!("could not start editor '{editor}'"))?;
    let body: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    Ok(body.join("\n").trim().to_string())
}

fn message_from(paths: &Paths, words: &[String], to: &str) -> anyhow::Result<String> {
    if words.is_empty() { edit_message(paths, to) } else { Ok(words.join(" ")) }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn print_code(code: &str, qr: bool) {
    println!("\n     {}\n", ui::accent(code));
    if qr && let Ok(q) = qrcode::QrCode::new(code.as_bytes()) {
        let img = q
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        println!("{img}\n");
    }
}

fn report_offline(r: &yo_cli::client::SyncReport, quiet: bool) {
    if quiet {
        return;
    }
    if let Some(e) = &r.offline {
        ui::warn(&format!("offline ({e}); showing what was already downloaded"));
    }
    for n in &r.notices {
        ui::info(n);
    }
}

async fn run(cli: Cli, paths: Paths) -> anyhow::Result<()> {
    let Some(cmd) = cli.cmd else {
        return overview(&paths).await;
    };
    match cmd {
        Cmd::Init { server, pin, token, link } => {
            println!("{}\n", ui::banner());
            if pin.is_none() {
                ui::warn("no --pin given: the server must have a certificate from a public CA");
            }
            let passphrase = new_passphrase()?;
            let opts = InitOptions { server: server.clone(), pin, token, passphrase, kdf: KdfParams::DEFAULT };
            let client = match &link {
                Some(code) => {
                    ui::info("linking to your account… (keep `yo link` running on your other device)");
                    Client::init_linked(paths.clone(), opts, code, |id| {
                        println!(
                            " This device is {}. Your other device will ask you to approve it.",
                            ui::accent(&id.short())
                        );
                    })
                    .await?
                }
                None => Client::init(paths.clone(), opts).await?,
            };
            ui::ok(&format!("yo! is ready on this device ({})", ui::dim(&client.me.short())));
            if link.is_some() {
                ui::ok(&format!("linked — {} contact(s) copied from your other device", client.contacts()?.len()));
            }
            println!("\nNext:");
            for (cmd, what) in [
                ("yo add <name>", "add someone"),
                ("yo prompt bash", "unread indicator for your prompt (also zsh, fish, powershell)"),
                ("yo daemon install", "background notifier + passphrase agent"),
            ] {
                println!("  {}  {}", ui::bold(&format!("{cmd:<18}")), ui::dim(what));
            }
        }

        Cmd::Add { name, code, qr, invite, as_name } => {
            let mut c = open(&paths).await?;
            let rel = if code.is_empty() {
                let who = name.clone();
                // With --invite, mint the newcomer's registration token first so
                // the whole block is ready the moment the code is.
                let init_line =
                    if invite { Some(c.admin_create_token(1, &format!("invite {name}")).await?.1) } else { None };
                let me_name = as_name
                    .or_else(|| std::env::var("USER").ok())
                    .or_else(|| std::env::var("USERNAME").ok())
                    .filter(|n| yo_cli::client::validate_name(n).is_ok())
                    .unwrap_or_else(|| "friend".into());

                c.add_open(&name, move |code| {
                    println!("{}", ui::rule(&format!("invite for {who}")));
                    match &init_line {
                        Some(init) => {
                            println!(" Send {who} all of this, over a channel you trust:\n");
                            println!("   {}", ui::dim("# 1. install (needs Rust; skip if they already have yo)"));
                            println!("   {}", ui::bold("cargo install --git https://github.com/jsprada/yo yo-cli"));
                            println!("   {}", ui::dim("# 2. join the server (asks for a passphrase), then add you:"));
                            println!("   {} && \\", ui::bold(init));
                            println!("   {}\n", ui::bold(&format!("yo add {me_name} {code}")));
                            println!(
                                " {}",
                                ui::dim(&format!(
                                    "The token works until used. The code works once and expires in 10 minutes while this \
                                     command waits; if it expires, run `yo add {who}` again and send only the new code."
                                ))
                            );
                        }
                        None => {
                            println!(" Give {who} this code (read it out, or send it somewhere you trust):");
                            print_code(code, qr);
                            println!(" They run:  {}", ui::bold(&format!("yo add {me_name} {code}")));
                            println!(
                                " {}",
                                ui::dim("Waiting… the code works once and expires in 10 minutes (Ctrl-C to cancel).")
                            );
                        }
                    }
                    if qr && init_line.is_some() {
                        print_code(code, true);
                    }
                })
                .await?
            } else {
                c.add_join(&name, &code.join("-")).await?
            };
            let words = c.safety_words(&rel.bundle.nickname)?;
            ui::ok(&format!("{} added — keys exchanged and verified by the code", ui::name(&rel.bundle.nickname)));
            println!("  {} {}", ui::dim("safety words:"), words.join(" "));
            println!("  Say hi:  {}", ui::bold(&format!("yo {} hey!", rel.bundle.nickname)));
        }

        Cmd::Read => {
            let mut c = open(&paths).await?;
            let r = c.sync().await?;
            report_offline(&r, false);
            let rows = c.take_unread()?;
            if rows.is_empty() {
                println!("{}", ui::dim("No new messages."));
                return Ok(());
            }
            println!(" {} {}", ui::accent("yo!"), ui::dim(&format!("── {} new", rows.len())));
            for (row, rel) in &rows {
                let quote = row.msg.reply_to.and_then(|u| c.quoted(rel, &u));
                print!("{}", ui::card(row, &rel.bundle.nickname, quote.as_ref(), true));
            }
        }

        Cmd::Reply { number, message } => {
            let n: i64 =
                number.trim_start_matches('#').parse().map_err(|_| anyhow!("'{number}' is not a message number"))?;
            let mut c = open(&paths).await?;
            let text = message_from(&paths, &message, &format!("message #{n}"))?;
            let (name, _, rep) = c.reply(n, &text).await?;
            ui::ok(&format!("replied to {} {}", ui::name(&name), ui::dim(&devices_note(&rep))));
        }

        Cmd::History { name, count } => {
            let mut c = open(&paths).await?;
            let r = c.sync().await?;
            report_offline(&r, false);
            let rel = c.contact(&name)?;
            let rows = c.store.history(&rel, count)?;
            println!("{}", ui::rule(&rel.bundle.nickname));
            if rows.is_empty() {
                println!("{}", ui::dim("   no messages yet"));
            }
            let mut ids = Vec::new();
            for row in &rows {
                let quote = row.msg.reply_to.and_then(|u| c.quoted(&rel, &u));
                print!("{}", ui::history_line(row, &rel.bundle.nickname, quote.as_ref()));
                if !row.read {
                    ids.push(row.id);
                }
            }
            c.store.mark_read(&ids)?;
            c.refresh_unread();
        }

        Cmd::Contacts => {
            let c = open(&paths).await?;
            let unread = c.store.unread_by_rel()?;
            let contacts = c.contacts()?;
            if contacts.is_empty() {
                println!("{}", ui::dim("No contacts yet. Add one with `yo add <name>`."));
            }
            for r in contacts {
                let n = unread.get(&r.id).copied().unwrap_or(0);
                let badge = if n > 0 { ui::accent(&format!("{n} new")) } else { String::new() };
                let v = if r.bundle.peer_rik.is_none() {
                    ui::dim("… invite not finished (run `yo add` again)")
                } else if r.bundle.verified {
                    ui::me("✔ verified")
                } else {
                    ui::red("? unverified")
                };
                println!(
                    " {:<20} {}  {}  {}",
                    ui::name(&r.bundle.nickname),
                    v,
                    ui::dim(&format!("since {}", ui::when(r.bundle.created_at))),
                    badge
                );
            }
        }

        Cmd::Rename { old, new } => {
            let mut c = open(&paths).await?;
            c.rename(&old, &new).await?;
            ui::ok(&format!("{old} is now {}", ui::name(&new)));
        }

        Cmd::Burn { name, yes, local } => {
            let mut c = open(&paths).await?;
            let rel = c.contact(&name)?;
            let nick = rel.bundle.nickname.clone();
            if !yes {
                if !interactive() {
                    bail!("refusing to burn without confirmation; pass --yes");
                }
                println!("{} This permanently destroys your conversation with {}:", ui::red("💥"), ui::name(&nick));
                println!("   • every message and key for it on this device and your other devices");
                println!("   • {nick}'s devices are told to destroy their copy as well");
                println!(
                    "   {}",
                    ui::dim(&format!(
                        "(yo! on {nick}'s side complies automatically; a modified client could keep a copy)"
                    ))
                );
                print!(" Type {} to confirm: ", ui::bold(&nick));
                std::io::stdout().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case(&nick) {
                    bail!("not confirmed; nothing was burned");
                }
            }
            match c.burn(&nick, local).await? {
                Some(rep) => {
                    ui::ok(&format!("burned — {nick}'s devices and yours were told {}", ui::dim(&devices_note(&rep))))
                }
                None => ui::ok("burned your local copy (nobody was notified)"),
            }
        }

        Cmd::Verify { name } => {
            let c = open(&paths).await?;
            let words = c.safety_words(&name)?;
            println!(" Safety words for {}:\n", ui::name(&name));
            println!("     {}\n", ui::accent(&words.join("  ")));
            println!(" Compare them with {name} in person or on the phone.");
            println!(" If they match, nobody is in the middle of your conversation.");
        }

        Cmd::Link { qr, yes } => {
            let mut c = open(&paths).await?;
            let cfg = c.cfg.clone();
            let id = c
                .link_open(
                    move |code| {
                        println!("{}", ui::rule("link a new device"));
                        println!(" On the new device run:\n");
                        let mut cmd = format!("yo init --server {}", cfg.server);
                        if let Some(p) = &cfg.pin {
                            cmd.push_str(&format!(" --pin {p}"));
                        }
                        cmd.push_str(&format!(" --link {code}"));
                        println!("     {}", ui::bold(&cmd));
                        print_code(code, qr);
                        ui::warn("whoever uses this code gets a copy of your account; keep it to yourself");
                        println!(" {}", ui::dim("Waiting… the code works once and expires in 5 minutes."));
                    },
                    move |device| {
                        if yes {
                            return true;
                        }
                        if !interactive() {
                            ui::error("a device wants to link but there is no terminal to confirm it on; use --yes");
                            return false;
                        }
                        print!(
                            " Device {} wants to link. It should show the same id. Send it your account? [y/N] ",
                            ui::accent(&device.short())
                        );
                        let _ = std::io::stdout().flush();
                        let mut answer = String::new();
                        let _ = std::io::stdin().read_line(&mut answer);
                        matches!(answer.trim(), "y" | "Y" | "yes")
                    },
                )
                .await?;
            ui::ok(&format!("linked device {}", ui::accent(&id.short())));
        }

        Cmd::Rekey { name, all } => {
            let mut c = open(&paths).await?;
            match (name, all) {
                (Some(n), false) => {
                    c.rekey_contact(&n).await?;
                    ui::ok(&format!("rotated the keys of your conversation with {}", ui::name(&n)));
                }
                (None, true) => {
                    let n = c.rekey_all().await?;
                    ui::ok(&format!("rotated {n} keys (every conversation and your device-sync key)"));
                }
                _ => bail!("give a contact name, or --all"),
            }
            println!(" {}", ui::dim("Contacts pick the new key up automatically on their next sync."));
        }

        Cmd::Devices { cmd } => {
            let mut c = open(&paths).await?;
            match cmd {
                None => {
                    let devs = c.devices().await?;
                    println!(" Your devices:");
                    for d in devs {
                        let this = if d.device == c.me { ui::me(" (this device)") } else { String::new() };
                        println!(
                            "   {}  {}{this}",
                            ui::accent(&d.device.short()),
                            ui::dim(&format!("added {}", ui::when(d.added_at)))
                        );
                    }
                    println!(" {}", ui::dim("Remove a lost device with: yo devices remove <id>"));
                }
                Some(DevicesCmd::Remove { id, no_rekey }) => {
                    let d = c.remove_device(&id, !no_rekey).await?;
                    ui::ok(&format!("removed device {} from all conversations", d.device.short()));
                    if no_rekey {
                        ui::warn(
                            "keys were not rotated: a stolen, unlocked device can still use its copies — run `yo rekey --all`",
                        );
                    } else {
                        ui::ok("rotated every conversation key; the removed device's copies are now useless");
                    }
                }
            }
        }

        Cmd::Unlock { minutes } => {
            let cfg = ClientConfig::load(&paths)?;
            let minutes = minutes.unwrap_or(if cfg.unlock_minutes == 0 { 15 } else { cfg.unlock_minutes });
            let kf = KeyFile::load(&paths.keyfile())?;
            let dk = kf.unlock(&read_passphrase("Passphrase: ")?)?;
            if agent::status(&paths).await.is_none() {
                daemon::spawn_background(&paths)?;
                if !daemon::wait_until_up(&paths).await {
                    bail!("the daemon did not start; see {}", paths.daemon_log().display());
                }
            }
            agent::unlock(&paths, &dk, minutes).await?;
            ui::ok(&format!("unlocked for {minutes} minutes after last use"));
        }

        Cmd::Lock => match agent::request(&paths, agent::AgentReq::Lock).await {
            Ok(_) => ui::ok("locked"),
            Err(_) => ui::ok("locked (the agent wasn't running)"),
        },

        Cmd::Passwd => {
            let kf = KeyFile::load(&paths.keyfile())?;
            let old = rpassword::prompt_password("Current passphrase: ")?;
            kf.unlock(&old)?;
            let new = new_passphrase()?;
            kf.rewrap(&old, &new)?.save(&paths.keyfile())?;
            ui::ok("passphrase changed");
        }

        Cmd::Sync { quiet } => {
            let cfg = ClientConfig::load(&paths)?;
            let key = if quiet { agent::get_key(&paths).await } else { Some(data_key(&paths, &cfg).await?) };
            match key {
                Some(dk) => {
                    let mut c = Client::open(paths.clone(), dk)?;
                    let r = c.sync().await?;
                    report_offline(&r, quiet);
                    if !quiet {
                        let n = c.store.unread_count()?;
                        ui::ok(&format!("{} unread", n));
                    }
                }
                None => {
                    // Locked: download (still encrypted) without decrypting.
                    if let Ok(mut conn) = yo_cli::net::Conn::connect(&paths, &cfg, None).await {
                        let _ = yo_cli::client::download_to_spool(&mut conn, &paths).await;
                    }
                    let _ = spool::refresh_unread(&paths, None);
                }
            }
        }

        Cmd::Daemon { cmd } => match cmd {
            DaemonCmd::Run => daemon::run(paths).await?,
            DaemonCmd::Start => {
                if agent::status(&paths).await.is_some() {
                    ui::ok("already running");
                } else {
                    daemon::spawn_background(&paths)?;
                    if daemon::wait_until_up(&paths).await {
                        ui::ok("daemon started");
                    } else {
                        bail!("the daemon did not start; see {}", paths.daemon_log().display());
                    }
                }
            }
            DaemonCmd::Stop => match agent::request(&paths, agent::AgentReq::Shutdown).await {
                Ok(_) => ui::ok("daemon stopped"),
                Err(_) => ui::ok("daemon was not running"),
            },
            DaemonCmd::Status => match agent::status(&paths).await {
                Some(s) => {
                    ui::ok(&format!("running (pid {})", s.pid));
                    println!("   server: {}", if s.connected { ui::me("connected") } else { ui::red("disconnected") });
                    match s.unlocked_for {
                        Some(t) => println!("   store:  unlocked ({}m left)", t / 60 + 1),
                        None => println!("   store:  locked"),
                    }
                    if let Some(e) = s.last_error {
                        println!("   last error: {}", ui::dim(&e));
                    }
                }
                None => println!("{}", ui::dim("not running — start it with `yo daemon start` or `yo daemon install`")),
            },
            DaemonCmd::Install => {
                ClientConfig::load(&paths)?;
                ui::ok(&service::install()?);
            }
            DaemonCmd::Uninstall => ui::ok(&service::uninstall()?),
        },

        Cmd::Prompt { shell, sync } => {
            let unread = std::path::absolute(paths.unread())?;
            print!("{}", yo_cli::prompt::snippet(shell, &unread, sync));
        }

        Cmd::Status => status(&paths).await?,

        Cmd::Admin { cmd } => {
            let mut c = open(&paths).await?;
            match cmd {
                AdminCmd::Token { uses, note } => {
                    let (token, line) = c.admin_create_token(uses, &note).await?;
                    ui::ok(&format!(
                        "token {} ({} registration{}{})",
                        ui::accent(&token),
                        uses,
                        if uses == 1 { "" } else { "s" },
                        if note.is_empty() { String::new() } else { format!(", {note}") }
                    ));
                    println!("\n Send them this line, over a channel you trust:\n");
                    println!("   {}\n", ui::bold(&line));
                    println!(
                        " {}",
                        ui::dim("They need Rust: cargo install --git https://github.com/jsprada/yo yo-cli")
                    );
                }
                AdminCmd::Tokens => {
                    let tokens = c.admin_tokens().await?;
                    if tokens.is_empty() {
                        println!("{}", ui::dim("No unspent tokens."));
                    }
                    for t in tokens {
                        println!(
                            " {}  {} left  {}  {}{}",
                            ui::accent(&t.token),
                            t.uses_left,
                            ui::dim(&format!("created {}", ui::when(t.created_at))),
                            t.note,
                            if t.grants_admin { ui::red(" [admin]") } else { String::new() }
                        );
                    }
                }
                AdminCmd::Revoke { token } => {
                    c.admin_revoke(&token).await?;
                    ui::ok("token revoked");
                }
                AdminCmd::Status => {
                    let s = c.admin_status().await?;
                    println!("{}", ui::rule(&format!("yo-server {}", s.version)));
                    let up = yo_proto::now().saturating_sub(s.started_at);
                    println!(
                        " up since        {} ({}d {}h {}m)",
                        ui::when(s.started_at),
                        up / 86400,
                        (up % 86400) / 3600,
                        (up % 3600) / 60
                    );
                    println!(" protocol        {}", s.protocol);
                    println!(" devices         {} ({} admin)", s.registered_devices, s.admins);
                    println!(" unspent tokens  {}", s.unspent_tokens);
                    println!(
                        " conversations   {} inboxes, {} queued envelopes, {} one-time keys",
                        s.live_inboxes, s.queued_envelopes, s.one_time_keys
                    );
                    println!(
                        " abuse counters  accepted {}, refused by IP {}, by device cap {}, registrations refused {}, rate-limited {}, live invites {}",
                        s.accepted,
                        s.refused_ip,
                        s.refused_device_conn,
                        s.refused_registration,
                        s.rate_limited,
                        s.live_mailboxes
                    );
                }
            }
        }

        Cmd::Send(args) => {
            let name = args.first().cloned().unwrap_or_default();
            let mut c = open(&paths).await?;
            if c.contact(&name).is_err() {
                let typo = |r: &&&str| {
                    let d = edit_distance(r, &name.to_ascii_lowercase());
                    d == 1 || (d == 2 && r.len() >= 4)
                };
                if let Some(cmd) = RESERVED.iter().find(typo) {
                    bail!("no contact named '{name}'. Did you mean `yo {cmd}`?");
                }
                c.contact(&name)?;
            }
            let text = message_from(&paths, &args[1..], &name)?;
            let (_, rep) = c.send_text(&name, &text, None).await?;
            ui::ok(&format!(
                "sent to {} {}",
                ui::name(&c.contact(&name)?.bundle.nickname),
                ui::dim(&devices_note(&rep))
            ));
        }
    }
    Ok(())
}

fn devices_note(r: &yo_cli::client::SendReport) -> String {
    let mut s = format!("({} device{}", r.delivered_to, if r.delivered_to == 1 { "" } else { "s" });
    if r.skipped > 0 {
        s.push_str(&format!(", {} unreachable", r.skipped));
    }
    s.push(')');
    s
}

async fn overview(paths: &Paths) -> anyhow::Result<()> {
    let cfg = match ClientConfig::load(paths) {
        Ok(c) => c,
        Err(StoreError::NotInitialized) => {
            println!("{}\n", ui::banner());
            println!(" Private, end-to-end encrypted messages from your terminal.\n");
            println!(" Get started:  {}", ui::bold("yo init --server HOST:PORT --pin sha256:..."));
            println!(" Help:         {}", ui::bold("yo --help"));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    if cfg.banner {
        println!("{}\n", ui::banner());
    }
    let n = spool::read_unread(paths);
    if n > 0 {
        println!(
            " {} {}",
            ui::accent(&format!("{n} new message{}", if n == 1 { "" } else { "s" })),
            ui::dim("— yo read")
        );
    } else {
        println!(" {}", ui::dim("No new messages."));
    }
    println!(" {}", ui::dim("yo <name> <message> · yo read · yo reply <#> · yo contacts · yo --help"));
    Ok(())
}

async fn status(paths: &Paths) -> anyhow::Result<()> {
    let cfg = ClientConfig::load(paths)?;
    println!(" server:   {}", cfg.server);
    println!(" pin:      {}", cfg.pin.as_deref().unwrap_or("(web PKI)"));
    match yo_proto::tls::load_chain_file(&paths.tls_cert()).ok().and_then(|c| yo_proto::tls::spki_hash(&c[0]).ok()) {
        Some(h) => println!(
            " device id: {}  (what `yo-server admin grant` takes)",
            yo_proto::DeviceId::from_spki_hash(&h).short()
        ),
        None => println!(" device:   {}", ui::red("certificate missing")),
    }
    println!(" data:     {}", paths.data_dir.display());
    match agent::status(paths).await {
        Some(s) => {
            println!(" daemon:   running, {}", if s.connected { "connected" } else { "not connected" });
            println!(" store:    {}", if s.unlocked_for.is_some() { "unlocked" } else { "locked" });
        }
        None => println!(" daemon:   not running"),
    }
    let t = std::time::Instant::now();
    match yo_cli::net::Conn::connect(paths, &cfg, None).await {
        Ok(_) => println!(" network:  {} ({} ms)", ui::me("ok"), t.elapsed().as_millis()),
        Err(e) => println!(" network:  {}", ui::red(&format!("{e:#}"))),
    }
    println!(" unread:   {}", spool::read_unread(paths));
    Ok(())
}
