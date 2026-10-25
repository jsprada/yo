//! Keeps docs/src/reference/commands.md in step with the real CLI: every
//! subcommand and every long option of `yo` and `yo-server` must appear.

use clap::CommandFactory;

fn walk(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let path = format!("{prefix} {}", sub.get_name());
        out.push(format!("`{path}"));
        for arg in sub.get_arguments() {
            if let Some(long) = arg.get_long()
                && long != "help"
                && long != "version"
            {
                out.push(format!("--{long}"));
            }
        }
        walk(sub, &path, out);
    }
}

#[test]
fn every_command_and_option_is_documented() {
    let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/src/reference/commands.md"))
        .expect("commands.md exists");
    let mut wanted = Vec::new();
    walk(&yo_cli::cli::Cli::command(), "yo", &mut wanted);
    let missing: Vec<&String> = wanted.iter().filter(|w| !doc.contains(w.as_str())).collect();
    assert!(missing.is_empty(), "missing from docs/src/reference/commands.md: {missing:?}");
}
