//! Exercise the audit host's AwP wiring against a declarative registry
//! document and a deterministic ACP agent double — no external model.
//! The host is driven exactly as the gate drives it: `--contract <dir>`
//! points at an installed checker payload (contract, installation,
//! registry, policy) and `--run <dir>` at this run's working directory.
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Stdio};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Fixture {
    contract_dir: PathBuf,
    run_dir: PathBuf,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "gitvault-acp-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let contract_dir = root.join("contract");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&contract_dir).unwrap();
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(root.join("acp.mode"), mode).unwrap();
        let stub_args = [PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/acp_agent.py")
            .to_string_lossy()
            .into_owned()];
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
        // The declared AwP document: both agent specs (program, args, env)
        // and the audit binding's fallback chain live in config, exactly as
        // the installer writes.
        let document = json!({
            "agents": {
                "opencode": {
                    "id": "opencode",
                    "lane": "acp",
                    "mcp_servers": [],
                    "prefer_load": true,
                    "command": {
                        "program": python.clone(),
                        "args": stub_args.clone(),
                        "env": {"sanitized": {"inherit": [], "set": {
                            "STUB_DIR": root.to_string_lossy(),
                            "STUB_MODEL": "opencode/stub-free",
                            "STUB_MODELS": "opencode/stub-free,opencode/glm-stub-free"
                        }}}
                    }
                },
                "devin": {
                    "id": "devin",
                    "lane": "acp",
                    "prefer_load": true,
                    "command": {
                        "program": python,
                        "args": stub_args,
                        "env": {"sanitized": {"inherit": [], "set": {
                            "STUB_DIR": root.to_string_lossy(),
                            "STUB_MODEL": "swe-2-max",
                            "STUB_MODELS": "swe-2-max",
                            "STUB_SESSION": "devin-stub-session"
                        }}}
                    }
                }
            },
            "profiles": {
                "synthetic-reviewer": {"agent": "opencode"},
                "synthetic-reviewer-devin": {"agent": "devin", "model": "swe-2-max"}
            },
            "bindings": {
                "audit": {"profile": "synthetic-reviewer", "prompt": "Binding context.",
                          "fallbacks": ["synthetic-reviewer-devin"]}
            }
        });
        std::fs::write(
            contract_dir.join("registry.json"),
            serde_json::to_string_pretty(&document).unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("contract.json"),
            serde_json::to_string_pretty(&json!({
                "name": "synthetic-reviewer",
                "title": "Synthetic Reviewer",
                "task": "synthetic audit"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("installation.json"),
            serde_json::to_string_pretty(&json!({
                "synced": {"tag": "profile/synthetic-reviewer/v1"},
                "review": "/bin/echo"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("policy.md"),
            "Only inspect synthetic evidence.",
        )
        .unwrap();
        std::fs::write(
            run_dir.join("scope.json"),
            serde_json::to_string_pretty(&json!({
                "runtime": {
                    "harness": "opencode",
                    "provider": "opencode",
                    "model": "opencode/stub-free"
                }
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            contract_dir,
            run_dir,
        }
    }
    /// The run directory the stub's fixtures land in — STUB_DIR's parent.
    fn stub_root(&self) -> PathBuf {
        self.contract_dir.parent().unwrap().to_path_buf()
    }
    fn write_document(&self, document: &Value) {
        std::fs::write(
            self.contract_dir.join("registry.json"),
            serde_json::to_string(document).unwrap(),
        )
        .unwrap();
    }
    fn document(&self) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(self.contract_dir.join("registry.json")).unwrap(),
        )
        .unwrap()
    }
    fn invoke(&self) -> (bool, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_gitvault-audit-agent"))
            .args([
                "--contract",
                self.contract_dir.to_str().unwrap(),
                "--run",
                self.run_dir.to_str().unwrap(),
            ])
            .current_dir(&self.run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(output.stdout.len() < 1024);
        let text = String::from_utf8(output.stdout).unwrap();
        let root = self.stub_root();
        assert!(!text.contains(root.to_str().unwrap()));
        (
            output.status.success(),
            serde_json::from_str(&text).unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(root) = self.contract_dir.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[test]
fn declared_document_completes_with_usage_and_composed_instructions() {
    let fixture = Fixture::new("complete");
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(
        result["profile"],
        json!({"id":"synthetic-reviewer",
        "revision":"profile/synthetic-reviewer/v1","principal":"profile:synthetic-reviewer"})
    );
    // Policy, the declared binding's standing prompt, then the task — AwP's
    // own composition order.
    let composed =
        std::fs::read_to_string(fixture.stub_root().join("fixture-instructions.txt")).unwrap();
    assert!(
        composed.starts_with(
            "Only inspect synthetic evidence.\n\nBinding context.\n\nReview date (UTC): "
        ) && composed.ends_with("\n\nsynthetic audit"),
        "{composed}"
    );
    assert_eq!(
        result["usage"],
        json!({"input_tokens":9,"output_tokens":4,
        "cache_read_tokens":2,"cache_write_tokens":1})
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.run_dir.join("audit-session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "acp-stub-session"
    );
    // The role's single MCP server reached the session declaration — `type`
    // is consumed as the wire discriminant; the stdio payload is what lands.
    let servers: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.stub_root().join("mcp_servers.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        servers,
        json!([{"name":"gitvault-audit","command":"/bin/echo","args":[
            "serve","--contract",
            fixture.contract_dir.join("contract.json").to_string_lossy(),
            "--run",
            fixture.run_dir.to_string_lossy(),
        ],"env":[]}])
    );
}

#[test]
fn agent_failures_never_complete() {
    for mode in ["failed", "interrupted", "disconnect"] {
        let fixture = Fixture::new(mode);
        let (_ok, result) = fixture.invoke();
        assert_eq!(result["completed"], false, "{mode}");
    }
}

#[test]
fn each_auditor_has_its_own_awp_principal() {
    for id in [
        "money-saver",
        "clean-auditor",
        "security-enhancer",
        "sustainable-maintainer",
    ] {
        let fixture = Fixture::new("complete");
        // Production installs one profile per checker under its own name:
        // contract name, profile key and binding target are the same.
        let mut contract: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture.contract_dir.join("contract.json")).unwrap(),
        )
        .unwrap();
        contract["name"] = json!(id);
        std::fs::write(
            fixture.contract_dir.join("contract.json"),
            serde_json::to_string(&contract).unwrap(),
        )
        .unwrap();
        let mut document = fixture.document();
        document["profiles"][id] = json!({"agent": "opencode"});
        document["bindings"]["audit"]["profile"] = json!(id);
        fixture.write_document(&document);
        let (ok, result) = fixture.invoke();
        assert!(ok);
        assert_eq!(result["profile"]["id"], id);
        assert_eq!(result["profile"]["principal"], format!("profile:{id}"));
    }
}

#[test]
fn inadmissible_roles_and_bindings_never_spawn_an_agent() {
    // The runtime's declared model chain outside the free OpenCode catalog
    // refuses the review before any agent spawns.
    for (runtime, policy) in [
        (
            json!({"harness": "unknown-agent", "provider": "opencode", "model": "opencode/stub-free"}),
            Some("Only inspect synthetic evidence."),
        ),
        (
            json!({"harness": "opencode", "provider": "opencode"}),
            Some("Only inspect synthetic evidence."),
        ),
        (
            json!({"harness": "opencode", "provider": "opencode",
                   "model": "opencode/stub-free", "models": ["openai/gpt-5"]}),
            Some("Only inspect synthetic evidence."),
        ),
        // An empty policy leaves the role without instructions — refused.
        (
            json!({"harness": "opencode", "provider": "opencode", "model": "opencode/stub-free"}),
            Some(""),
        ),
    ] {
        let fixture = Fixture::new("complete");
        let mut scope: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture.run_dir.join("scope.json")).unwrap(),
        )
        .unwrap();
        scope["runtime"] = runtime;
        std::fs::write(
            fixture.run_dir.join("scope.json"),
            serde_json::to_string(&scope).unwrap(),
        )
        .unwrap();
        if let Some(policy) = policy {
            std::fs::write(fixture.contract_dir.join("policy.md"), policy).unwrap();
        }
        let (ok, result) = fixture.invoke();
        assert!(!ok, "{result}");
        assert!(
            !fixture
                .stub_root()
                .join("fixture-instructions.txt")
                .exists()
        );
    }
    // A binding pointing at an unprojected profile fails closed too: the
    // contract names `other-reviewer` while the audit binding still
    // resolves `synthetic-reviewer`.
    let fixture = Fixture::new("complete");
    let mut contract: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.contract_dir.join("contract.json")).unwrap(),
    )
    .unwrap();
    contract["name"] = json!("other-reviewer");
    std::fs::write(
        fixture.contract_dir.join("contract.json"),
        serde_json::to_string(&contract).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert!(
        !fixture
            .stub_root()
            .join("fixture-instructions.txt")
            .exists()
    );
}

#[test]
fn an_exhausted_model_falls_back_within_the_same_session() {
    let fixture = Fixture::new("complete");
    // The declared model is quota-dead; the role's chain offers the next
    // free OpenCode model.
    let mut document = fixture.document();
    document["agents"]["opencode"]["command"]["env"]["sanitized"]["set"]["STUB_QUOTA"] =
        json!("opencode/stub-free");
    fixture.write_document(&document);
    let mut scope: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.run_dir.join("scope.json")).unwrap())
            .unwrap();
    scope["runtime"]["models"] = json!(["opencode/glm-stub-free"]);
    std::fs::write(
        fixture.run_dir.join("scope.json"),
        serde_json::to_string(&scope).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["agent"], "opencode");
    assert_eq!(result["served"]["model"], "opencode/glm-stub-free");
    // One session, one model switch: prompt@stub-free → set_config_option →
    // prompt@glm-stub-free.
    let trace: Vec<Value> = std::fs::read_to_string(fixture.stub_root().join("stub-trace.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let events: Vec<String> = trace
        .iter()
        .map(|entry| {
            format!(
                "{}@{}",
                entry["method"].as_str().unwrap_or(""),
                entry["model"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        events,
        vec![
            "session/prompt@opencode/stub-free",
            "session/set_config_option@opencode/glm-stub-free",
            "session/prompt@opencode/glm-stub-free",
        ]
    );
}

#[test]
fn an_unavailable_agent_yields_to_the_declared_fallback() {
    let fixture = Fixture::new("complete");
    let mut document = fixture.document();
    document["agents"]["opencode"]["command"]["program"] = json!("/nonexistent-agent");
    fixture.write_document(&document);
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["profile"], "synthetic-reviewer-devin");
    assert_eq!(result["served"]["agent"], "devin");
    assert_eq!(result["served"]["model"], "swe-2-max");
    // The fallback is a fresh session on a different agent, but the role —
    // policy, binding prompt, task — lands identically.
    let composed =
        std::fs::read_to_string(fixture.stub_root().join("fixture-instructions.txt")).unwrap();
    assert!(
        composed.starts_with(
            "Only inspect synthetic evidence.\n\nBinding context.\n\nReview date (UTC): "
        ) && composed.ends_with("\n\nsynthetic audit"),
        "{composed}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.run_dir.join("audit-session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "devin-stub-session"
    );
}

#[test]
fn a_missing_agent_program_is_classified_without_local_details() {
    let fixture = Fixture::new("complete");
    let mut document = fixture.document();
    // Every declared candidate is absent: the chain exhausts and the
    // refusal still carries no local paths.
    document["agents"]["opencode"]["command"]["program"] = json!("/nonexistent-agent");
    document["agents"]["devin"]["command"]["program"] = json!("/nonexistent-fallback");
    fixture.write_document(&document);
    let (ok, result) = fixture.invoke();
    assert!(!ok);
    assert_eq!(result["completed"], false);
    assert!(result["failure"]["code"].is_string());
}
