//! Exercise the audit host's AwP wiring against a declarative registry
//! document and a deterministic ACP agent double — no external model.
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Fixture(PathBuf);
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
        std::fs::create_dir(&root).unwrap();
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
            root.join("registry.json"),
            serde_json::to_string_pretty(&document).unwrap(),
        )
        .unwrap();
        Self(root)
    }
    fn request(&self) -> Value {
        json!({
            "document": self.0.join("registry.json"),
            "prompt": "synthetic audit",
            "role": {"id":"synthetic-reviewer","name":"Synthetic Reviewer","agent":"opencode",
                    "revision":"profile/synthetic-reviewer/v1","model":"opencode/stub-free",
                    "permission":"read-only","instructions":"Only inspect synthetic evidence.",
                    "mcpServers":[{"type":"stdio","name":"gitvault-audit",
                                    "command":"/bin/echo","args":[],"env":[]}],
                    "extensions":{"provider":"opencode"}},
            "resume":null,"session_file":self.0.join("session.json"),
            "run_dir":self.0,
        })
    }
    fn invoke(&self) -> (bool, Value) {
        self.invoke_request(self.request())
    }
    fn invoke_request(&self, request: Value) -> (bool, Value) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gitvault-audit-agent"))
            .current_dir(&self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.len() < 1024);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(self.0.to_str().unwrap()));
        (
            output.status.success(),
            serde_json::from_str(&text).unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("fixture-instructions.txt")).unwrap(),
        "Only inspect synthetic evidence.\n\nBinding context.\n\nsynthetic audit"
    );
    assert_eq!(
        result["usage"],
        json!({"input_tokens":9,"output_tokens":4,
        "cache_read_tokens":2,"cache_write_tokens":1})
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.0.join("session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "acp-stub-session"
    );
    // The role's single MCP server reached the session declaration — `type`
    // is consumed as the wire discriminant; the stdio payload is what lands.
    let servers: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.0.join("mcp_servers.json")).unwrap())
            .unwrap();
    assert_eq!(
        servers,
        json!([{"name":"gitvault-audit","command":"/bin/echo","args":[],"env":[]}])
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
        let mut request = fixture.request();
        request["role"]["id"] = json!(id);
        let mut document: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture.0.join("registry.json")).unwrap(),
        )
        .unwrap();
        // Production installs one profile per checker under its own name:
        // profile key, binding target and projected role id are the same.
        document["profiles"][id] = json!({"agent": "opencode"});
        document["bindings"]["audit"]["profile"] = json!(id);
        std::fs::write(
            fixture.0.join("registry.json"),
            serde_json::to_string(&document).unwrap(),
        )
        .unwrap();
        let (ok, result) = fixture.invoke_request(request);
        assert!(ok);
        assert_eq!(result["profile"]["id"], id);
        assert_eq!(result["profile"]["principal"], format!("profile:{id}"));
    }
}

#[test]
fn inadmissible_roles_and_bindings_never_spawn_an_agent() {
    for (field, value) in [
        ("agent", json!("unknown-agent")),
        ("permission", json!("danger-full-access")),
        ("model", Value::Null),
        ("instructions", Value::Null),
        (
            "mcpServers",
            json!([{"type":"stdio","name":"foreign-tools","command":"/bin/echo"}]),
        ),
        // The free-tier restriction binds the whole model chain, not just
        // the primary.
        ("models", json!(["openai/gpt-5"])),
    ] {
        let fixture = Fixture::new("complete");
        let mut request = fixture.request();
        request["role"][field] = value;
        let (ok, result) = fixture.invoke_request(request);
        assert!(!ok, "{result}");
        assert!(!fixture.0.join("fixture-instructions.txt").exists());
    }
    // A binding pointing at an unprojected profile fails closed too.
    let fixture = Fixture::new("complete");
    let mut request = fixture.request();
    request["role"]["id"] = json!("other-reviewer");
    let (ok, result) = fixture.invoke_request(request);
    assert!(!ok, "{result}");
    assert!(!fixture.0.join("fixture-instructions.txt").exists());
}

#[test]
fn an_exhausted_model_falls_back_within_the_same_session() {
    let fixture = Fixture::new("complete");
    // The declared model is quota-dead; the role's chain offers the next
    // free OpenCode model.
    let mut document: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.0.join("registry.json")).unwrap())
            .unwrap();
    document["agents"]["opencode"]["command"]["env"]["sanitized"]["set"]["STUB_QUOTA"] =
        json!("opencode/stub-free");
    std::fs::write(
        fixture.0.join("registry.json"),
        serde_json::to_string(&document).unwrap(),
    )
    .unwrap();
    let mut request = fixture.request();
    request["role"]["models"] = json!(["opencode/glm-stub-free"]);
    let (ok, result) = fixture.invoke_request(request);
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["agent"], "opencode");
    assert_eq!(result["served"]["model"], "opencode/glm-stub-free");
    // One session, one model switch: prompt@stub-free → set_config_option →
    // prompt@glm-stub-free.
    let trace: Vec<Value> = std::fs::read_to_string(fixture.0.join("stub-trace.jsonl"))
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
    let mut document: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.0.join("registry.json")).unwrap())
            .unwrap();
    document["agents"]["opencode"]["command"]["program"] = json!("/nonexistent-agent");
    std::fs::write(
        fixture.0.join("registry.json"),
        serde_json::to_string(&document).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["profile"], "synthetic-reviewer-devin");
    assert_eq!(result["served"]["agent"], "devin");
    assert_eq!(result["served"]["model"], "swe-2-max");
    // The fallback is a fresh session on a different agent, but the role —
    // policy, binding prompt, task — lands identically.
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("fixture-instructions.txt")).unwrap(),
        "Only inspect synthetic evidence.\n\nBinding context.\n\nsynthetic audit"
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.0.join("session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "devin-stub-session"
    );
}

#[test]
fn a_missing_agent_program_is_classified_without_local_details() {
    let fixture = Fixture::new("complete");
    let mut document: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.0.join("registry.json")).unwrap())
            .unwrap();
    // Every declared candidate is absent: the chain exhausts and the
    // refusal still carries no local paths.
    document["agents"]["opencode"]["command"]["program"] = json!("/nonexistent-agent");
    document["agents"]["devin"]["command"]["program"] = json!("/nonexistent-fallback");
    std::fs::write(
        fixture.0.join("registry.json"),
        serde_json::to_string(&document).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(!ok);
    assert_eq!(result["completed"], false);
    assert!(result["failure"]["code"].is_string());
}
