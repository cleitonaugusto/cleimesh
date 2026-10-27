//! `cleimesh setup openclaw|hermes`: the separate-user setup of
//! docs/separate-user.md in one command, then the agent pointed at the node
//! with its own file and shell tools turned off.
//!
//! The plan is built by pure functions from what was found on the machine,
//! so it can be printed (`--dry-run`) and tested without root. Running it
//! shows the plan, asks once, and stops at the first step that fails; `sudo`
//! asks for the password itself. Steps already done are skipped, so running
//! it again only re-issues the tokens (they last `--days`).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// Where the node runs and the binary its service starts.
pub const BIN: &str = "/usr/local/bin/cleimesh";
const UNIT: &str = "/etc/systemd/system/cleimesh.service";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    Openclaw,
    Hermes,
}

impl Agent {
    fn name(self) -> &'static str {
        match self {
            Agent::Openclaw => "openclaw",
            Agent::Hermes => "hermes",
        }
    }
}

/// OpenClaw's own tools that reach files or a shell (its tool policy names).
pub const OPENCLAW_NATIVE: [&str; 7] = ["read", "write", "edit", "apply_patch", "exec", "process", "ls"];
/// Hermes' toolsets that reach files, a shell, a browser or the desktop.
pub const HERMES_NATIVE: [&str; 5] = ["terminal", "file", "browser", "code_execution", "computer_use"];

#[derive(Clone, Debug)]
pub struct Options {
    pub agent: Agent,
    /// Directories the agent may read; reading them does not taint.
    pub read: Vec<PathBuf>,
    /// Directories with outside content (mail, downloads): reading them taints.
    pub untrusted: Vec<PathBuf>,
    /// Directories the agent may write; refused while its chain is tainted.
    pub write: Vec<PathBuf>,
    pub user: String,
    pub port: u16,
    pub days: u64,
}

/// What was found on the machine before planning.
#[derive(Clone, Debug, Default)]
pub struct Found {
    /// This binary is already installed at [`BIN`], owned by root.
    pub installed: bool,
    pub user_exists: bool,
    /// The unit file exists with exactly the content we would write.
    pub unit_current: bool,
    pub service_active: bool,
}

/// One command of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub what: String,
    pub argv: Vec<String>,
    /// Fed to the command's standard input.
    pub stdin: Option<String>,
}

fn step(what: impl Into<String>, argv: &[&str]) -> Step {
    Step { what: what.into(), argv: argv.iter().map(|s| s.to_string()).collect(), stdin: None }
}

pub fn unit_file(port: u16, user: &str) -> String {
    format!(
        "[Unit]\nDescription=CleiMesh node\nAfter=network.target\n\n[Service]\nUser={user}\nExecStart={BIN} start --listen /ip4/127.0.0.1/tcp/{port}\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

/// The steps that need root: binary, user, service.
pub fn system_steps(o: &Options, found: &Found, exe: &Path, unit_tmp: &Path) -> Vec<Step> {
    let mut steps = Vec::new();
    if !found.installed {
        let exe = exe.to_string_lossy();
        steps.push(step("install this binary where the agent cannot replace it", &["sudo", "install", "-m", "755", "-o", "root", "-g", "root", &exe, BIN]));
    }
    if !found.user_exists {
        steps.push(step(
            format!("create the node's user `{}`", o.user),
            &["sudo", "useradd", "--system", "--create-home", "--home-dir", &format!("/var/lib/{}", o.user), "--shell", "/usr/sbin/nologin", &o.user],
        ));
    }
    if !found.unit_current {
        let tmp = unit_tmp.to_string_lossy();
        steps.push(step("write the node's systemd service", &["sudo", "install", "-m", "644", "-o", "root", "-g", "root", &tmp, UNIT]));
        steps.push(step("reload systemd", &["sudo", "systemctl", "daemon-reload"]));
    }
    if !found.service_active || !found.unit_current || !found.installed {
        steps.push(step("start the node now and at boot", &["sudo", "systemctl", "enable", "--now", "cleimesh"]));
        if found.service_active {
            steps.push(step("restart it on the new binary or unit", &["sudo", "systemctl", "restart", "cleimesh"]));
        }
    }
    steps
}

/// ACLs so the node's user can reach the granted directories and nothing
/// else: `x` on each of your directories above them (pass, not list), `rX`
/// or `rwX` on the directories themselves, also as default for new files.
/// Only entries `uid` owns: the files the node wrote are its own already, and
/// `setfacl` on them fails, which broke running setup again.
pub fn acl_steps(o: &Options, home: &Path, uid: u32) -> Vec<Step> {
    let uid = uid.to_string();
    let mut steps = Vec::new();
    let mut passed = Vec::<PathBuf>::new();
    let grants = o.read.iter().chain(&o.untrusted).map(|d| (d, "rX")).chain(o.write.iter().map(|d| (d, "rwX")));
    for (dir, perm) in grants {
        let mut above: Vec<&Path> = dir.ancestors().skip(1).filter(|a| a.starts_with(home)).collect();
        above.reverse();
        for a in above {
            if !passed.iter().any(|p| p == a) {
                passed.push(a.to_path_buf());
                steps.push(step(format!("let `{}` pass through {}", o.user, a.display()), &["setfacl", "-m", &format!("u:{}:x", o.user), &a.to_string_lossy()]));
            }
        }
        let d = dir.to_string_lossy();
        let acl = format!("u:{}:{}", o.user, perm);
        steps.push(step(
            format!("let `{}` {} {}", o.user, if perm == "rwX" { "read and write" } else { "read" }, dir.display()),
            &["find", &d, "-user", &uid, "-exec", "setfacl", "-m", &acl, "{}", "+"],
        ));
        steps.push(step(
            format!("same for files created later in {}", dir.display()),
            &["find", &d, "-type", "d", "-user", &uid, "-exec", "setfacl", "-d", "-m", &acl, "{}", "+"],
        ));
    }
    steps
}

/// One token per kind of grant: `(file name, token issue arguments)`.
pub fn token_args(o: &Options, agent_id: &str) -> Vec<(&'static str, Vec<String>)> {
    let ttl = (o.days * 24 * 3600).to_string();
    let mut tokens = Vec::new();
    let mut issue = |file: &'static str, tool: &str, flag: &str, dirs: &[PathBuf], mark: Option<&str>| {
        if dirs.is_empty() {
            return;
        }
        let mut args: Vec<String> = ["token", "issue", agent_id, "--tool", tool].iter().map(|s| s.to_string()).collect();
        for d in dirs {
            args.push(flag.into());
            args.push(d.to_string_lossy().into_owned());
        }
        args.extend(mark.map(str::to_string));
        args.extend(["--ttl".to_string(), ttl.clone()]);
        tokens.push((file, args));
    };
    issue("read.json", "file_read", "--read", &o.read, None);
    issue("untrusted.json", "file_read", "--read", &o.untrusted, Some("--taints"));
    issue("write.json", "file_write", "--write", &o.write, Some("--clean-only"));
    tokens
}

/// `mcp serve` arguments: forward to the node with every token.
pub fn serve_args(addr: &str, tokens: &[PathBuf]) -> Vec<String> {
    let mut args = vec!["mcp".to_string(), "serve".into(), "--node".into(), addr.into()];
    for t in tokens {
        args.push("--token".into());
        args.push(t.to_string_lossy().into_owned());
    }
    args
}

/// `tools.deny` for OpenClaw: what is there plus its own file and shell tools.
pub fn openclaw_deny(current: &Value) -> Vec<String> {
    let mut deny: Vec<String> = current["tools"]["deny"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
    for t in OPENCLAW_NATIVE {
        if !deny.iter().any(|d| d == t) {
            deny.push(t.to_string());
        }
    }
    deny
}

/// Registering CleiMesh with the agent and turning its own tools off, through
/// the agent's own commands (validated writes that keep the user's comments).
pub fn agent_steps(o: &Options, serve: &[String], registered: bool, openclaw_config: &Value) -> Vec<Step> {
    let mut steps = Vec::new();
    match o.agent {
        Agent::Openclaw => {
            if registered {
                steps.push(step("drop the old CleiMesh entry", &["openclaw", "mcp", "unset", "cleimesh"]));
            }
            let mut add = vec!["openclaw", "mcp", "add", "cleimesh", "--command", BIN];
            for a in serve {
                add.push("--arg");
                add.push(a);
            }
            steps.push(step("register CleiMesh as OpenClaw's MCP server", &add));
            let patch = serde_json::json!({ "tools": { "deny": openclaw_deny(openclaw_config) } });
            let mut s = step("turn off OpenClaw's own file and shell tools", &["openclaw", "config", "patch", "--stdin"]);
            s.stdin = Some(patch.to_string());
            steps.push(s);
        }
        Agent::Hermes => {
            if registered {
                let mut s = step("drop the old CleiMesh entry", &["hermes", "mcp", "remove", "cleimesh"]);
                s.stdin = Some("y\n".into());
                steps.push(s);
            }
            let mut add = vec!["hermes", "mcp", "add", "cleimesh", "--command", BIN, "--args"];
            add.extend(serve.iter().map(String::as_str));
            let mut s = step("register CleiMesh as Hermes' MCP server", &add);
            // "Enable all tools?" when Hermes reaches the server. When it
            // cannot, the same answer saves the entry disabled: see
            // `hermes_enabled`, checked right after this step.
            s.stdin = Some("Y\n".into());
            steps.push(s);
            let mut off = vec!["hermes", "tools", "disable"];
            off.extend(HERMES_NATIVE);
            steps.push(step("turn off Hermes' own terminal, file, browser and code tools", &off));
        }
    }
    steps
}

/// Whether `~/.hermes/config.yaml` has a server running CleiMesh, under any
/// name, and it is on. `hermes mcp add` saves it with `enabled: false` when
/// it cannot start it (without Hermes' optional MCP support, for one).
pub fn hermes_enabled(config: &str) -> bool {
    let docs = yaml_rust2::YamlLoader::load_from_str(config).unwrap_or_default();
    let servers = docs.first().and_then(|d| d["mcp_servers"].as_hash().cloned()).unwrap_or_default();
    servers.values().any(|s| {
        let mentions = |v: &yaml_rust2::Yaml| v.as_str().is_some_and(|t| t.contains("cleimesh"));
        let runs = mentions(&s["command"]) || s["args"].as_vec().is_some_and(|a| a.iter().any(mentions));
        runs && s["enabled"].as_bool() != Some(false)
    })
}

/// Hermes' own toolsets still on for the CLI, from `~/.hermes/config.yaml`.
/// Without `platform_toolsets.cli` the default preset (everything) applies.
pub fn hermes_native_on(config: &str) -> Vec<&'static str> {
    let docs = yaml_rust2::YamlLoader::load_from_str(config).unwrap_or_default();
    let cli = docs.first().map(|d| &d["platform_toolsets"]["cli"]);
    let Some(list) = cli.and_then(|c| c.as_vec()) else { return HERMES_NATIVE.to_vec() };
    let names: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
    // Presets and composites that include them.
    if names.iter().any(|n| n.starts_with("hermes-") || *n == "all" || *n == "debugging") {
        return HERMES_NATIVE.to_vec();
    }
    HERMES_NATIVE.iter().copied().filter(|t| names.contains(t)).collect()
}

fn found_on_machine(o: &Options, exe: &Path) -> Found {
    let same = |a: &Path, b: &Path| std::fs::read(a).ok().zip(std::fs::read(b).ok()).is_some_and(|(x, y)| x == y);
    let root_owned = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(BIN).is_ok_and(|m| m.uid() == 0)
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let quiet = |argv: &[&str]| Command::new(argv[0]).args(&argv[1..]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    Found {
        installed: root_owned && same(exe, Path::new(BIN)),
        user_exists: quiet(&["id", "-u", &o.user]),
        unit_current: std::fs::read_to_string(UNIT).is_ok_and(|u| u == unit_file(o.port, &o.user)),
        service_active: quiet(&["systemctl", "is-active", "--quiet", "cleimesh"]),
    }
}

fn run_step(s: &Step) -> anyhow::Result<()> {
    let mut cmd = Command::new(&s.argv[0]);
    cmd.args(&s.argv[1..]);
    if s.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("cannot run {}: {}", s.argv[0], e))?;
    if let (Some(input), Some(mut stdin)) = (&s.stdin, child.stdin.take()) {
        stdin.write_all(input.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("`{}` failed ({})", s.argv.join(" "), status);
    }
    Ok(())
}

/// Runs a command as the node's user, from `/` (a directory it can enter).
fn as_node(user: &str, args: &[String]) -> anyhow::Result<String> {
    let out = Command::new("sudo").args(["-u", user, "-H", BIN]).args(args).current_dir("/").stderr(Stdio::inherit()).output()?;
    if !out.status.success() {
        anyhow::bail!("`sudo -u {} {} {}` failed ({})", user, BIN, args.join(" "), out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn show(steps: &[Step]) {
    for s in steps {
        println!("  - {}\n      {}", s.what, s.argv.join(" "));
        if let Some(input) = &s.stdin {
            println!("      with input: {}", input.trim_end());
        }
    }
}

/// Writes a file only you can read (`0600`), also when it already exists.
#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(text.as_bytes())
}

fn confirm() -> anyhow::Result<bool> {
    print!("Go ahead? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "sim" | "s"))
}

fn absolute(dirs: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    dirs.iter().map(|d| std::fs::canonicalize(d).map_err(|e| anyhow::anyhow!("{}: {}", d.display(), e))).collect()
}

#[cfg(unix)]
pub fn run(mut o: Options, client_key: PathBuf, dry_run: bool, yes: bool) -> cleimesh_core::Result<()> {
    run_inner(&mut o, client_key, dry_run, yes).map_err(Into::into)
}

// The plan is sudo, systemd, setfacl and file modes: Linux only for now.
#[cfg(not(unix))]
pub fn run(_: Options, _: PathBuf, _: bool, _: bool) -> cleimesh_core::Result<()> {
    Err(anyhow::anyhow!("cleimesh setup runs on Linux (sudo, systemd, setfacl); see docs/separate-user.md").into())
}

#[cfg(unix)]
fn run_inner(o: &mut Options, client_key: PathBuf, dry_run: bool, yes: bool) -> anyhow::Result<()> {
    if o.read.is_empty() && o.untrusted.is_empty() && o.write.is_empty() {
        anyhow::bail!("grant at least one directory: --read, --untrusted or --write");
    }
    // `mcp serve` presents the first chain that grants a tool, so two
    // file_read tokens can't be told apart by path yet.
    if !o.read.is_empty() && !o.untrusted.is_empty() {
        anyhow::bail!("--read and --untrusted both grant file_read, and one agent can hold only one file_read token for now; set up the untrusted folders for a second agent, or grant them all with --untrusted");
    }
    if !(1..=90).contains(&o.days) {
        anyhow::bail!("--days must be between 1 and 90 (the longest a root token may live)");
    }
    o.read = absolute(&o.read)?;
    o.untrusted = absolute(&o.untrusted)?;
    o.write = absolute(&o.write)?;
    let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?);
    let exe = std::env::current_exe()?;
    let tokens_dir = home.join(".config").join("cleimesh").join(o.agent.name());
    let unit_tmp = std::env::temp_dir().join(format!("cleimesh.service.{}", std::process::id()));

    let found = found_on_machine(o, &exe);
    let system = system_steps(o, &found, &exe, &unit_tmp);
    // SAFETY: getuid has no preconditions and cannot fail.
    let acls = acl_steps(o, &home, unsafe { libc::getuid() });
    let token_files: Vec<PathBuf> = token_args(o, "<AGENT_ID>").iter().map(|(f, _)| tokens_dir.join(f)).collect();
    let config_path = match o.agent {
        Agent::Openclaw => home.join(".openclaw").join("openclaw.json"),
        Agent::Hermes => home.join(".hermes").join("config.yaml"),
    };
    let config_text = std::fs::read_to_string(&config_path).unwrap_or_default();
    let registered = config_text.contains("cleimesh");
    let openclaw_config: Value = json5::from_str(&config_text).unwrap_or(Value::Null);
    let addr_shown = format!("/ip4/127.0.0.1/tcp/{}/p2p/<NODE_ID>", o.port);

    println!("cleimesh setup {}: the node runs as `{}`, the agent reaches it only through `mcp serve --node`.\n", o.agent.name(), o.user);
    println!("As root (sudo asks for your password):");
    if system.is_empty() { println!("  (nothing: binary, user and service are already in place)") } else { show(&system) }
    println!("\nAs you:");
    show(&acls);
    println!("  - the node issues the agent's tokens, valid {} days, into {}", o.days, tokens_dir.display());
    for (file, args) in token_args(o, "<AGENT_ID>") {
        println!("      sudo -u {} -H {} {}  > {}", o.user, BIN, args.join(" "), file);
    }
    show(&agent_steps(o, &serve_args(&addr_shown, &token_files), registered, &openclaw_config));
    println!("  - check it all: cleimesh doctor\n");
    if dry_run {
        return Ok(());
    }
    if !yes && !confirm()? {
        println!("Nothing changed.");
        return Ok(());
    }

    std::fs::write(&unit_tmp, unit_file(o.port, &o.user))?;
    let system_result = system.iter().try_for_each(run_step);
    let _ = std::fs::remove_file(&unit_tmp);
    system_result?;
    acls.iter().try_for_each(run_step)?;

    // The service writes its key on first start.
    let mut node_id = Err(anyhow::anyhow!("the node did not start"));
    for _ in 0..50 {
        node_id = as_node(&o.user, &["id".into()]);
        if node_id.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let node_id = node_id?;
    let agent_id = cleimesh_p2p::node_key::load_or_generate(&client_key).map_err(|e| anyhow::anyhow!("{}", e))?.public().to_peer_id().to_string();

    std::fs::create_dir_all(&tokens_dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tokens_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut files = Vec::new();
    for (file, args) in token_args(o, &agent_id) {
        let chain = as_node(&o.user, &args)?;
        let path = tokens_dir.join(file);
        write_private(&path, &(chain + "\n"))?;
        files.push(path);
    }
    let addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", o.port, node_id);
    for s in agent_steps(o, &serve_args(&addr, &files), registered, &openclaw_config) {
        run_step(&s)?;
        // Stop before turning Hermes' own tools off, or it would have none.
        if s.argv[..3] == ["hermes", "mcp", "add"] && !hermes_enabled(&std::fs::read_to_string(&config_path).unwrap_or_default()) {
            anyhow::bail!(
                "Hermes did not enable CleiMesh (it saves the server disabled when it cannot start it, for one without its MCP support); \
                 so its own tools were not turned off. Run `hermes setup` to install MCP support, then run this command again"
            );
        }
    }

    println!("\nDone. The node is {addr}.");
    println!("Renew the tokens before they expire in {} days by running the same command again.", o.days);
    println!("Clear a taint: sudo systemctl stop cleimesh; cd /; sudo -u {} cleimesh taint list; sudo -u {} cleimesh taint clear <HOLDER> --reason \"...\"; sudo systemctl start cleimesh\n", o.user, o.user);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(agent: Agent) -> Options {
        Options {
            agent,
            read: vec![],
            untrusted: vec![PathBuf::from("/home/ana/mail/inbox")],
            write: vec![PathBuf::from("/home/ana/mail/out")],
            user: "cleimesh".into(),
            port: 7400,
            days: 30,
        }
    }

    #[test]
    fn a_fresh_machine_gets_binary_user_service_and_start() {
        let steps = system_steps(&opts(Agent::Openclaw), &Found::default(), Path::new("/home/ana/.cargo/bin/cleimesh"), Path::new("/tmp/u"));
        let what: Vec<&str> = steps.iter().map(|s| s.argv[1].as_str()).collect();
        assert_eq!(what, ["install", "useradd", "install", "systemctl", "systemctl"]);
        assert!(steps.iter().all(|s| s.argv[0] == "sudo"));
        assert!(steps[0].argv.contains(&BIN.to_string()));
    }

    #[test]
    fn a_machine_already_set_up_needs_no_root() {
        let found = Found { installed: true, user_exists: true, unit_current: true, service_active: true };
        assert!(system_steps(&opts(Agent::Hermes), &found, Path::new(BIN), Path::new("/tmp/u")).is_empty());
    }

    #[test]
    fn a_new_binary_restarts_the_running_node() {
        let found = Found { installed: false, user_exists: true, unit_current: true, service_active: true };
        let steps = system_steps(&opts(Agent::Hermes), &found, Path::new("/x"), Path::new("/tmp/u"));
        assert_eq!(steps.last().unwrap().argv, ["sudo", "systemctl", "restart", "cleimesh"]);
    }

    #[test]
    fn the_unit_runs_the_root_owned_binary_as_the_node_user_on_localhost() {
        let unit = unit_file(7400, "cleimesh");
        assert!(unit.contains("User=cleimesh\n"));
        assert!(unit.contains(&format!("ExecStart={} start --listen /ip4/127.0.0.1/tcp/7400\n", BIN)));
    }

    #[test]
    fn acls_pass_through_each_parent_once_and_grant_only_the_directories() {
        let steps = acl_steps(&opts(Agent::Openclaw), Path::new("/home/ana"), 1000);
        let pass: Vec<&str> = steps.iter().filter(|s| s.argv[0] == "setfacl" && s.argv[2].ends_with(":x")).map(|s| s.argv[3].as_str()).collect();
        assert_eq!(pass, ["/home/ana", "/home/ana/mail"]);
        assert!(steps.iter().any(|s| s.argv == ["find", "/home/ana/mail/inbox", "-user", "1000", "-exec", "setfacl", "-m", "u:cleimesh:rX", "{}", "+"]));
        assert!(steps.iter().any(|s| s.argv == ["find", "/home/ana/mail/out", "-user", "1000", "-exec", "setfacl", "-m", "u:cleimesh:rwX", "{}", "+"]));
        assert!(steps.iter().any(|s| s.argv == ["find", "/home/ana/mail/out", "-type", "d", "-user", "1000", "-exec", "setfacl", "-d", "-m", "u:cleimesh:rwX", "{}", "+"]));
    }

    #[cfg(unix)]
    #[test]
    fn tokens_are_written_for_you_alone_even_over_an_old_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("write.json");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, "new\n").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[test]
    fn untrusted_reads_taint_and_writes_are_clean_only() {
        let tokens = token_args(&opts(Agent::Openclaw), "AGENT");
        let names: Vec<&str> = tokens.iter().map(|(f, _)| *f).collect();
        assert_eq!(names, ["untrusted.json", "write.json"]);
        assert!(tokens[0].1.contains(&"--taints".to_string()) && tokens[0].1.contains(&"file_read".to_string()));
        assert!(tokens[1].1.contains(&"--clean-only".to_string()) && tokens[1].1.contains(&"--write".to_string()));
        assert!(tokens.iter().all(|(_, a)| a.windows(2).any(|w| w[0] == "--ttl" && w[1] == (30 * 24 * 3600).to_string())));
    }

    #[test]
    fn openclaw_keeps_the_users_denials_and_adds_its_own_tools() {
        let deny = openclaw_deny(&serde_json::json!({"tools": {"deny": ["browser", "exec"]}}));
        assert_eq!(deny[0], "browser");
        assert_eq!(deny.iter().filter(|d| *d == "exec").count(), 1);
        assert!(OPENCLAW_NATIVE.iter().all(|t| deny.iter().any(|d| d == t)));
    }

    #[test]
    fn openclaw_registration_forwards_to_the_node_and_patches_the_policy() {
        let serve = serve_args("/ip4/127.0.0.1/tcp/7400/p2p/N", &[PathBuf::from("/t/w.json")]);
        let steps = agent_steps(&opts(Agent::Openclaw), &serve, true, &Value::Null);
        assert_eq!(steps[0].argv, ["openclaw", "mcp", "unset", "cleimesh"]);
        let add = steps[1].argv.join(" ");
        assert!(add.contains(&format!("--command {} --arg mcp --arg serve --arg --node --arg /ip4/127.0.0.1/tcp/7400/p2p/N --arg --token --arg /t/w.json", BIN)));
        assert!(steps[2].stdin.as_deref().unwrap().contains("\"apply_patch\""));
    }

    #[test]
    fn hermes_registration_answers_its_prompt_and_disables_its_toolsets() {
        let serve = serve_args("/ip4/127.0.0.1/tcp/7400/p2p/N", &[]);
        let steps = agent_steps(&opts(Agent::Hermes), &serve, false, &Value::Null);
        assert_eq!(steps[0].argv[..7], ["hermes", "mcp", "add", "cleimesh", "--command", BIN, "--args"]);
        assert_eq!(steps[0].stdin.as_deref(), Some("Y\n"));
        assert_eq!(steps[1].argv[3..], HERMES_NATIVE);
        let again = agent_steps(&opts(Agent::Hermes), &serve, true, &Value::Null);
        assert_eq!((again[0].argv[2].as_str(), again[0].stdin.as_deref()), ("remove", Some("y\n")));
    }

    // Seen in Docker: without Hermes' MCP support, the "Y" meant for
    // "Enable all tools?" answered "Save config anyway?" and the server was
    // saved disabled.
    #[test]
    fn hermes_counts_cleimesh_only_when_saved_and_on() {
        let on = "mcp_servers:\n  cleimesh:\n    command: /usr/local/bin/cleimesh\n    args: [mcp, serve]\n";
        assert!(hermes_enabled(on));
        assert!(hermes_enabled(&format!("{on}    enabled: true\n")));
        assert!(!hermes_enabled(&format!("{on}    enabled: false\n")));
        assert!(!hermes_enabled("mcp_servers:\n  other:\n    command: npx\n"));
        assert!(hermes_enabled(&on.replace("  cleimesh:", "  mesh:")));
        assert!(!hermes_enabled(""));
    }

    #[test]
    fn hermes_tools_are_on_by_default_and_off_when_left_out() {
        assert_eq!(hermes_native_on("model: x\n"), HERMES_NATIVE);
        assert_eq!(hermes_native_on("platform_toolsets:\n  cli: [hermes-cli]\n"), HERMES_NATIVE);
        assert_eq!(hermes_native_on("platform_toolsets:\n  cli:\n    - web\n    - terminal\n"), ["terminal"]);
        assert!(hermes_native_on("platform_toolsets:\n  cli: [web, memory, todo]\n").is_empty());
    }
}
