//! The installer: a checker lands on a machine as a contract, a policy, and a
//! registry entry - no code of its own. Ported from the retired Python
//! installer: one implementation, so the behavior that must never drift
//! (registry replacement, symlink conflict handling, bundle verification) has
//! exactly one home.

use crate::contract::{self, Contract};
use serde_json::{Map, Value, json};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The two well-known roots every checker lives under.
fn profile_root() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".hermes")
        .join("profiles")
}

fn skill_root() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".agents")
        .join("skills")
}

/// The registry file the gate binary actually reads: the same precedence
/// config.rs applies - $GITVAULT_CONFIG, then $XDG_CONFIG_HOME/gitvault, then
/// ~/.config/gitvault.
fn config_file() -> PathBuf {
    if let Ok(explicit) = std::env::var("GITVAULT_CONFIG")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        });
    base.join("gitvault").join("config.toml")
}

fn sha256(text: &str) -> String {
    sha2::Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The payload a checker installs: its contract, plus the document catalog
/// when the contract declares one.
fn payload_of(contract: &Contract) -> Vec<&'static str> {
    let mut payload = vec!["contract.json"];
    if contract.tools.official_documents {
        payload.push("documents.json");
    }
    payload
}

/// The audit agent home: an isolated XDG tree the OpenCode audit session runs
/// under. The runner fills it at launch (`config`, `data`, `state`, `cache`);
/// the only host material is a credentials link into the operator's existing
/// OpenCode store - never a credential copy, never a host configuration.
fn prepare_agent_home(profile: &Path) -> Result<String, String> {
    let home_root = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let host_data = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&home_root).join(".local").join("share"));
    let store = host_data.join("opencode");
    let links: Vec<PathBuf> = ["auth.json", "account.json"]
        .iter()
        .map(|name| store.join(name))
        .filter(|source| source.is_file())
        .collect();
    if links.is_empty() {
        return Err("An existing OpenCode sign-in is required for the audit runtime".to_string());
    }
    let home = profile.join("opencode");
    for leaf in ["config", "data", "state", "cache"] {
        std::fs::create_dir_all(home.join(leaf)).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
    }
    let data = home.join("data").join("opencode");
    std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    for source in links {
        let link = data.join(source.file_name().unwrap_or_default());
        if link.is_symlink() {
            let points = std::fs::canonicalize(&link).map_err(|e| e.to_string())?;
            if points != std::fs::canonicalize(&source).map_err(|e| e.to_string())? {
                return Err(format!(
                    "The audit agent home's {} link points to a different account store",
                    source.display()
                ));
            }
        } else if link.exists() {
            return Err(format!(
                "The audit agent home already contains an independent {}",
                source.display()
            ));
        } else {
            std::os::unix::fs::symlink(
                std::fs::canonicalize(&source).map_err(|e| e.to_string())?,
                &link,
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(home.to_string_lossy().into_owned())
}

/// The per-run OpenCode configuration the declared agent spec carries:
/// sharing and self-update off, the opencode-only provider wall, and a
/// fail-closed tool surface (no edits, shell, web or sub-agents). The model
/// is the profile's business — declared at runtime, applied by AwP's session
/// configuration path, never baked into the agent document.
fn opencode_config() -> Value {
    json!({
        "share": "disabled",
        "autoupdate": false,
        "snapshot": false,
        "formatter": false,
        "lsp": false,
        "plugin": [],
        "enabled_providers": ["opencode"],
        "permission": {
            "edit": "deny",
            "bash": "deny",
            "webfetch": "deny",
            "doom_loop": "deny",
            "external_directory": "deny",
        },
        "tools": {
            "write": false,
            "edit": false,
            "patch": false,
            "bash": false,
            "webfetch": false,
            "websearch": false,
            "task": false,
            "skill": false,
            "question": false,
            "todowrite": false,
            "todoread": false,
            "codesearch": false,
        },
    })
}

/// The checker's declared AwP registry document: the materialized agent
/// spec plus its standing `audit` binding. The runner resolves this file
/// through AwP's standard registry and overlays the runtime-projected role —
/// nothing about a specific agent is wired into the runner itself.
fn write_registry_document(
    target: &Path,
    contract: &Contract,
    opencode: &str,
    devin: &str,
) -> Result<(), String> {
    let isolated_xdg: Vec<String> = [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
    ]
    .iter()
    .map(|key| key.to_string())
    .collect();
    let mut spec = a4aa_opencode::spec();
    spec.command.program = opencode.to_string();
    spec.command.env = a4aa::EnvPolicy::Sanitized {
        inherit: isolated_xdg.clone(),
        set: BTreeMap::from([(
            "OPENCODE_CONFIG_CONTENT".to_string(),
            a4aa::EnvValue::Literal(opencode_config().to_string()),
        )]),
    };
    // Two protocol lanes for the same agent, ordered native-first: the
    // `serve` HTTP surface is polled request/response — the `acp` lane's
    // internal event subscriber cannot overflow because it never exists.
    // When the server cannot start or serve, the ACP alternate carries the
    // identical configuration.
    let mut serve = spec.clone();
    serve.lane = a4aa::LaneSpec::Serve {
        mcp_servers: vec![],
    };
    serve.command.args = vec!["serve".to_string(), "--port".to_string(), "0".to_string()];
    // The cross-agent fallback: same audit role on `devin acp`. Credentials
    // never enter the document — the lane's `auth_key` resolves the host's
    // DEVIN_API_KEY at session establishment, and a host without one simply
    // exhausts the chain. DEVIN_MODEL pins the declared model at spawn so the
    // selection holds whether or not the session advertises a model
    // configOption.
    const FALLBACK_MODEL: &str = "swe-2-max";
    let mut fallback = a4aa_devin::spec();
    fallback.command.program = devin.to_string();
    fallback.command.env = a4aa::EnvPolicy::Sanitized {
        inherit: isolated_xdg,
        set: BTreeMap::from([(
            "DEVIN_MODEL".to_string(),
            a4aa::EnvValue::Literal(FALLBACK_MODEL.to_string()),
        )]),
    };
    // The profile stub declares only which agent serves the role; the
    // engine's runtime projection supplies the role's model, policy and tool
    // surface on top of it. The fallback profile carries its own agent's
    // model — a different catalog than the primary's.
    let id = spec.id.clone();
    let fallback_id = fallback.id.clone();
    let fallback_profile = format!("{}-{fallback_id}", contract.name);
    let opencode_entry = awp::AgentEntry {
        spec: serve,
        alternates: vec![spec],
    };
    let document = json!({
        "agents": BTreeMap::from([
            (id.clone(), serde_json::to_value(&opencode_entry).map_err(|e| e.to_string())?),
            (fallback_id.clone(), serde_json::to_value(&fallback).map_err(|e| e.to_string())?),
        ]),
        "profiles": BTreeMap::from([
            (contract.name.clone(), json!({"agent": id})),
            (fallback_profile.clone(), json!({"agent": fallback_id, "model": FALLBACK_MODEL})),
        ]),
        "bindings": {"audit": {"profile": contract.name, "fallbacks": [fallback_profile]}},
    });
    let path = target.join("registry.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The files the drift check covers: the copied payload plus the generated
/// registry document, so a hand-edited agent declaration refuses the run.
fn installed_files(contract: &Contract) -> Vec<&'static str> {
    let mut names = payload_of(contract);
    names.push("registry.json");
    names
}

fn which(name: &str) -> Option<String> {
    let from_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    });
    if from_path.is_some() || name != "opencode" {
        return from_path;
    }
    // The self-installed OpenCode binary lives outside PATH on a fresh login.
    let candidate = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".opencode")
        .join("bin")
        .join("opencode");
    candidate
        .is_file()
        .then(|| candidate.to_string_lossy().into_owned())
}

/// The fallback agent's binary: PATH first, then the Devin app's bundled
/// CLI. Absent installs keep the bare name — a candidate that cannot spawn
/// simply yields to the next chain entry.
fn devin_program() -> String {
    which("devin")
        .or_else(|| {
            let candidate = Path::new(
                "/Applications/Devin.app/Contents/Resources/app/extensions/windsurf/devin/bin/devin",
            );
            candidate
                .is_file()
                .then(|| candidate.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "devin".to_string())
}

/// Add or replace this checker's registry entry. Replacing rather than
/// refusing keeps an installed checker updatable: the command embeds absolute
/// paths, so a machine that refused to touch an existing entry would be
/// stranded on whatever was written first.
fn register(config: &Path, name: &str, block: &str) -> Result<&'static str, String> {
    let text = std::fs::read_to_string(config).unwrap_or_default();
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with('[') && !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
        current.push_str(line);
    }
    if !current.is_empty() {
        segments.push(current);
    }
    let needle = format!("name = \"{name}\"");
    let mut action = "added";
    let mut replaced = false;
    for (index, segment) in segments.iter().enumerate() {
        if segment.trim_start().starts_with("[[checkers]]") && segment.contains(&needle) {
            segments[index] = block.to_string();
            action = "replaced";
            replaced = true;
            break;
        }
    }
    if !replaced {
        let separator = if text.ends_with("\n\n") || text.is_empty() {
            ""
        } else {
            "\n"
        };
        segments.push(format!("{separator}{block}"));
    }
    let updated = segments.concat();
    toml::from_str::<toml::Value>(&updated).map_err(|error| format!("config.toml: {error}"))?;
    std::fs::write(config, updated).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o600));
    }
    Ok(action)
}

fn read_installation(target: &Path) -> Option<Map<String, Value>> {
    std::fs::read_to_string(target.join("installation.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| value.as_object().cloned())
}

/// The payload's hashes, recorded so a later startup can tell an edited
/// payload apart from the one the installer wrote.
fn payload_hashes(target: &Path, payload: &[&str]) -> Result<Map<String, Value>, String> {
    let mut hashes = Map::new();
    for name in payload {
        let text =
            std::fs::read_to_string(target.join(name)).map_err(|e| format!("{name}: {e}"))?;
        hashes.insert(name.to_string(), json!(sha256(&text)));
    }
    Ok(hashes)
}

/// Copy the checker's documents and payload into place. Documents are the
/// registry's to publish: the source tree's copies seed a machine that has
/// never pulled; once a version is synced, `--pull` is the only thing that
/// overwrites them.
fn install_payload(source: &Path, target: &Path, contract: &Contract) -> Result<(), String> {
    let agent = &contract.name;
    let shared = skill_root().join(agent);
    std::fs::create_dir_all(&shared).map_err(|e| e.to_string())?;
    let synced = read_installation(target).is_some_and(|settings| settings.contains_key("synced"));
    if !synced {
        for name in ["SKILL.md", "policy.md"] {
            std::fs::copy(source.join(name), shared.join(name))
                .map_err(|e| format!("{name}: {e}"))?;
        }
    }
    // Every agent host's skills directory links the one shared copy:
    // home.glob(".*/skills"), home.glob(".config/*/skills") and
    // PROFILE_ROOT.glob("*/skills").
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&home) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .filter(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with('.')
                })
                .map(|p| p.join("skills")),
        );
    }
    if let Ok(entries) = std::fs::read_dir(home.join(".config")) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .map(|p| p.join("skills")),
        );
    }
    if let Ok(entries) = std::fs::read_dir(profile_root()) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .map(|p| p.join("skills")),
        );
    }
    let shared_real = std::fs::canonicalize(&shared).unwrap_or_else(|_| shared.clone());
    let shared_parent = shared
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_else(|| shared.clone());
    for directory in roots {
        if !directory.is_dir() {
            continue;
        }
        let directory_real = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.clone());
        if directory_real == shared_parent {
            continue;
        }
        let link = directory.join(agent);
        if link.is_symlink()
            && std::fs::canonicalize(&link).ok().as_deref() == Some(shared_real.as_path())
        {
            continue;
        }
        if link.exists() || link.is_symlink() {
            return Err(format!(
                "Conflicting {agent} skill entry requires inspection: {}",
                link.display()
            ));
        }
        std::os::unix::fs::symlink(&shared, &link).map_err(|e| e.to_string())?;
    }
    for name in payload_of(contract) {
        std::fs::copy(source.join(name), target.join(name)).map_err(|e| format!("{name}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(target.join(name), std::fs::Permissions::from_mode(0o600));
        }
    }
    // The policy rides the payload directory as a link into the shared skill
    // copy, so the registry's version is the only version in play.
    let destination = target.join("policy.md");
    if destination.exists() || destination.is_symlink() {
        let _ = std::fs::remove_file(&destination);
    }
    std::os::unix::fs::symlink(shared.join("policy.md"), &destination)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The registry block for one checker, in the signed config's own shape.
fn checker_block(contract: &Contract, target: &Path) -> Result<String, String> {
    let events = serde_json::to_string(&contract.on).map_err(|e| e.to_string())?;
    let runner = std::env::current_exe().map_err(|e| e.to_string())?;
    let command = json!([
        runner.to_string_lossy(),
        "run",
        "--contract",
        target.join("contract.json").to_string_lossy(),
        "--repo",
        "{repo}",
    ]);
    Ok(format!(
        "[[checkers]]\nname = \"{}\"\non = {}\nkind = \"exec\"\nseverity = \"blocking\"\ntimeout_secs = 0\ncommand = {}\n",
        contract.name,
        events,
        serde_json::to_string(&command).map_err(|e| e.to_string())?,
    ))
}

/// Install a checker from its source directory (`tools/<checker>/`).
pub fn install(source: &Path) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let (Some(opencode), Some(runner)) = (which("opencode"), which("gitvault-audit-agent")) else {
        return Err("OpenCode and gitvault-audit-agent (the A4AA runner) are required".to_string());
    };
    let profile = profile_root().join(&contract.name);
    let target = profile.join("plugins").join(&contract.name);
    if !profile.exists() {
        std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    } else if !target.join("installation.json").is_file() {
        return Err(format!(
            "Existing {} profile requires inspection before installation",
            contract.name
        ));
    }
    std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let agent_home = prepare_agent_home(&profile)?;
    install_payload(source, &target, &contract)?;
    write_registry_document(&target, &contract, &opencode, &devin_program())?;
    let previous = read_installation(&target).unwrap_or_default();
    let mut settings = json!({
        "program": opencode,
        "agent_home": agent_home,
        "agent_runner": runner,
        "profile": profile.to_string_lossy(),
        "skill_dir": skill_root().join(&contract.name).to_string_lossy(),
        "payload": payload_hashes(&target, &installed_files(&contract))?,
    });
    // Installing again does not un-sync anything.
    if let Some(synced) = previous.get("synced") {
        settings["synced"] = synced.clone();
    }
    write_settings(&target, &settings)?;
    let registry = config_file();
    if let Some(parent) = registry.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if !registry.exists() {
        std::fs::write(&registry, "").map_err(|e| e.to_string())?;
    }
    let action = register(
        &registry,
        &contract.name,
        &checker_block(&contract, &target)?,
    )?;
    Ok(format!(
        "{} installed: blocking {}; registry entry {action} in {}",
        contract.title,
        contract.on.join(", "),
        registry.display()
    ))
}

/// The payload file names the Python implementation installed - removed on
/// update, so the contract is the only thing left.
const RETIRED_PAYLOAD: [&str; 10] = [
    "__init__.py",
    "clean_stage1.py",
    "security_stage1.py",
    "maintainer_stage1.py",
    "full_audit.py",
    "audit.py",
    "plugin.yaml",
    "profile_sync.py",
    "codex_config.py",
    "audit_runtime.py",
];

/// Refresh an installed checker's payload from its source directory and
/// re-register its entry; the retired Python payload files leave with it.
pub fn update(source: &Path) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let (Some(opencode), Some(runner)) = (which("opencode"), which("gitvault-audit-agent")) else {
        return Err("OpenCode and gitvault-audit-agent (the A4AA runner) are required".to_string());
    };
    let profile = profile_root().join(&contract.name);
    let target = profile.join("plugins").join(&contract.name);
    let Some(mut settings) = read_installation(&target) else {
        return Err(format!("{} is not installed", contract.title));
    };
    // Legacy records predate the OpenCode runtime; the record migrates in
    // place so the checker never consults a removed harness.
    settings.remove("hermes");
    settings.remove("pi");
    settings.remove("credential_file");
    settings.remove("python");
    settings.remove("codex");
    settings.remove("codex_home");
    settings.insert("program".into(), json!(opencode));
    settings.insert("agent_runner".into(), json!(runner));
    settings.insert("agent_home".into(), json!(prepare_agent_home(&profile)?));
    for retired in RETIRED_PAYLOAD {
        let _ = std::fs::remove_file(target.join(retired));
    }
    let _ = std::fs::remove_file(target.join("review_ranges.py"));
    let _ = std::fs::remove_file(target.join("audit_engine.py"));
    install_payload(source, &target, &contract)?;
    write_registry_document(&target, &contract, &opencode, &devin_program())?;
    settings.insert(
        "payload".into(),
        Value::Object(payload_hashes(&target, &installed_files(&contract))?),
    );
    write_settings(&target, &Value::Object(settings))?;
    let registry = config_file();
    let action = register(
        &registry,
        &contract.name,
        &checker_block(&contract, &target)?,
    )?;
    Ok(format!(
        "Updated {} payload and registry entry ({action})",
        contract.title
    ))
}

fn write_settings(target: &Path, settings: &Value) -> Result<(), String> {
    let path = target.join("installation.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(settings).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The bundle decides what the agent runs, so the channel must be
/// authenticated anywhere it can be intercepted: loopback http is the local
/// development registry, anything else is https or refused.
fn check_url(url: &str) -> Result<(), String> {
    let parts = url.split_once("://");
    let loopback = ["127.0.0.1", "::1", "localhost"].iter().any(|host| {
        parts.is_some_and(|(_, rest)| rest.split(['/', ':', '?']).next() == Some(host))
    });
    if parts.is_some_and(|(scheme, _)| scheme == "https") || loopback {
        return Ok(());
    }
    Err(format!(
        "profile registry outside loopback must be reached over https: {url}"
    ))
}

/// The whole version as one value: one line per file, sorted — the registry's
/// own shape (`lines.join("\n") + "\n"`), byte-identical so a bundle's
/// published manifest verifies.
fn bundle_manifest(files: &Map<String, Value>) -> String {
    let mut lines: Vec<String> = files
        .keys()
        .map(|name| format!("{name}\t{}", sha256(files[name].as_str().unwrap_or(""))))
        .collect();
    lines.sort();
    sha256(&(lines.join("\n") + "\n"))
}

/// Fetch one published profile version and install its documents. Every hash
/// is checked before the first byte is written.
pub fn pull(source: &Path, tag: Option<&str>) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let target = profile_root()
        .join(&contract.name)
        .join("plugins")
        .join(&contract.name);
    // The registry decides which prompt and runtime the checker runs on, so
    // the channel is a choice the operator made - never whatever happens to
    // be listening on the port.
    let url = std::env::var("GITVAULT_PROFILES_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            "GITVAULT_PROFILES_URL is not set; the profile registry is an explicit choice"
                .to_string()
        })?;
    pull_with(&contract, &target, &url, tag)
}

fn pull_with(
    contract: &Contract,
    target: &Path,
    url: &str,
    tag: Option<&str>,
) -> Result<String, String> {
    let Some(settings) = read_installation(target) else {
        return Err(format!("{} is not installed", contract.title));
    };
    check_url(url)?;
    let mut endpoint = format!(
        "{}/api/gitvault/profiles/{}/bundle",
        url.trim_end_matches('/'),
        contract.name
    );
    if let Some(tag) = tag {
        endpoint += &format!("?tag={tag}");
    }
    let body = ureq::get(&endpoint)
        .header("accept", "application/json")
        .call()
        .map_err(|error| format!("the profile bundle could not be fetched: {error}"))?
        .into_body()
        .read_to_string()
        .map_err(|error| format!("the profile bundle could not be read: {error}"))?;
    let bundle: Value =
        serde_json::from_str(&body).map_err(|e| format!("the profile bundle: {e}"))?;
    let files = bundle["files"].as_object().cloned().unwrap_or_default();
    let hashes = bundle["hashes"].as_object().cloned().unwrap_or_default();
    let mut file_names: Vec<&String> = files.keys().collect();
    let mut hash_names: Vec<&String> = hashes.keys().collect();
    file_names.sort();
    hash_names.sort();
    if file_names != hash_names {
        return Err("The published profile listing is inconsistent; nothing was written".into());
    }
    if bundle_manifest(&files) != bundle["manifest"].as_str().unwrap_or("") {
        return Err(
            "The published profile manifest does not match its files; nothing was written".into(),
        );
    }
    for (name, text) in &files {
        if sha256(text.as_str().unwrap_or("")) != hashes[name].as_str().unwrap_or("") {
            return Err(format!(
                "The published copy of {name} does not match its hash; nothing was written"
            ));
        }
    }
    const SYNCED: [&str; 4] = ["policy.md", "SKILL.md", "documents.json", "profile.json"];
    let skill_dir = settings
        .get("skill_dir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| skill_root().join(&contract.name));
    std::fs::create_dir_all(&skill_dir).map_err(|e| e.to_string())?;
    let mut kept = Map::new();
    for name in SYNCED {
        if let Some(text) = files.get(name) {
            std::fs::write(skill_dir.join(name), text.as_str().unwrap_or(""))
                .map_err(|e| format!("{name}: {e}"))?;
            kept.insert(name.to_string(), hashes[name].clone());
        }
    }
    let stale = skill_dir.join("documents.json");
    if !kept.contains_key("documents.json") && stale.exists() {
        let _ = std::fs::remove_file(&stale);
    }
    let bundle_tag = bundle["tag"].as_str().unwrap_or("").to_string();
    let version = bundle_tag
        .rsplit_once("/v")
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .unwrap_or(0);
    let mut updated = settings;
    updated.insert("skill_dir".into(), json!(skill_dir.to_string_lossy()));
    updated.insert(
        "synced".into(),
        json!({"tag": bundle_tag, "version": version, "manifest": bundle["manifest"], "files": kept}),
    );
    write_settings(target, &Value::Object(updated))?;
    Ok(format!(
        "{} profile synced to {} ({} documents)",
        contract.name,
        bundle["tag"].as_str().unwrap_or(""),
        kept.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::{bundle_manifest, check_url, payload_of, pull_with, register};
    use crate::contract;
    use serde_json::{Value, json};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn contract_at(dir: &Path, official_documents: bool) -> contract::Contract {
        let mut text = json!({
            "name": "sample-checker",
            "title": "Sample Checker",
            "domains": ["structure"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push", "pr"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "official_documents": official_documents,
                "descriptions": {"context": "c", "submit": "s"}
            },
            "task": "Review."
        });
        if official_documents {
            text["tools"]["descriptions"]["official_doc"] = json!("Fetch by key.");
        }
        std::fs::write(
            dir.join("contract.json"),
            serde_json::to_string_pretty(&text).unwrap(),
        )
        .unwrap();
        contract::load(&dir.join("contract.json")).unwrap()
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn registry_blocks_replace_by_name_and_validate_as_toml() {
        let dir = tempdir();
        let config = dir.join("config.toml");
        std::fs::write(&config, "[identities.a]\nname = 'A'\n").unwrap();
        let block_a =
            "[[checkers]]\nname = \"one\"\non = [\"pre-push\"]\ncommand = [\"/bin/true\"]\n";
        assert_eq!(register(&config, "one", block_a).unwrap(), "added");
        let block_b = "[[checkers]]\nname = \"two\"\non = [\"pr\"]\ncommand = [\"/bin/false\"]\n";
        assert_eq!(register(&config, "two", block_b).unwrap(), "added");
        let block_new = "[[checkers]]\nname = \"one\"\non = [\"pr\"]\ncommand = [\"/bin/sh\"]\n";
        assert_eq!(register(&config, "one", block_new).unwrap(), "replaced");
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(
            text.contains("[identities.a]"),
            "unrelated sections survive"
        );
        assert!(text.contains("/bin/sh"), "the replacement landed");
        assert!(!text.contains("/bin/true\""), "the old block is gone");
        assert!(
            text.contains("name = \"two\""),
            "the other checker survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_payload_is_the_contract_and_maybe_a_catalog() {
        let dir = tempdir();
        assert_eq!(payload_of(&contract_at(&dir, false)), vec!["contract.json"]);
        assert_eq!(
            payload_of(&contract_at(&dir, true)),
            vec!["contract.json", "documents.json"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registry_urls_are_https_or_loopback() {
        assert!(check_url("http://127.0.0.1:8891").is_ok());
        assert!(check_url("http://localhost:8891").is_ok());
        assert!(check_url("https://registry.example.com").is_ok());
        assert!(check_url("http://registry.example.com").is_err());
    }

    /// Serve one canned registry bundle.
    fn serve_bundle(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let mut sink = String::new();
                while reader.read_line(&mut sink).is_ok_and(|n| n > 2) {}
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        url
    }

    #[test]
    fn pull_verifies_the_bundle_before_writing() {
        let dir = tempdir();
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let contract = contract_at(&source, false);
        let skill_dir = dir.join("skill");
        std::fs::write(
            target.join("installation.json"),
            json!({"skill_dir": skill_dir.to_string_lossy()}).to_string(),
        )
        .unwrap();
        let files = json!({"policy.md": "the policy\n", "SKILL.md": "the skill\n"});
        let hashes = json!({
            "policy.md": super::sha256("the policy\n"),
            "SKILL.md": super::sha256("the skill\n"),
        });
        let bundle = json!({
            "tag": "profile/sample-checker/v3",
            "manifest": bundle_manifest(files.as_object().unwrap()),
            "files": files,
            "hashes": hashes,
        });
        let url = serve_bundle(bundle.to_string());
        let message = pull_with(&contract, &target, &url, None).unwrap();
        assert!(message.contains("v3"), "{message}");
        assert_eq!(
            std::fs::read_to_string(skill_dir.join("policy.md")).unwrap(),
            "the policy\n"
        );
        let settings: Value = serde_json::from_str(
            &std::fs::read_to_string(target.join("installation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(settings["synced"]["tag"], "profile/sample-checker/v3");

        // A tampered file hash refuses the bundle and writes nothing.
        let target2 = dir.join("target2");
        let skill2 = dir.join("skill2");
        std::fs::create_dir_all(&target2).unwrap();
        std::fs::write(
            target2.join("installation.json"),
            json!({"skill_dir": skill2.to_string_lossy()}).to_string(),
        )
        .unwrap();
        let mut bad = bundle.clone();
        bad["files"]["policy.md"] = json!("edited\n");
        let url = serve_bundle(bad.to_string());
        assert!(pull_with(&contract, &target2, &url, None).is_err());
        assert!(!skill2.join("policy.md").exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
