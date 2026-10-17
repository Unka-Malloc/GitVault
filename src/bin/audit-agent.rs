//! OpenCode audit host. The checker declares its agent and binding in an AwP
//! registry document (`registry.json`, written by the installer). This host
//! fires as `gitvault-audit-agent --contract <contract.json> --run <dir>` and
//! derives the whole review surface from the installation itself: the
//! checker's role, its one MCP tool server, the run's scope and any resume
//! binding all live in the two directories it is pointed at. AwP owns
//! resolution, materialization and instruction composition; A4AA owns the
//! lane and process lifetime. This host contributes only the gate's
//! admission rules, the fail-closed permission handler and the settled
//! outcome the gate persists.
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a4aa::proto::acp::{PermissionDecision, PermissionPrompt};
use a4aa::{AgentEvent, PermissionHandler, SessionRequest, TurnRequest};
use serde_json::{Value, json};

/// Everything the run needs, derived from the two paths the gate hands over:
/// the installed contract directory and this run's working directory.
struct Request {
    /// <contract dir>/registry.json — the AwP document declaring the audit
    /// agent and the `audit` binding.
    document: PathBuf,
    prompt: String,
    /// The projected role: identity, policy, model and the review's one MCP
    /// tool server.
    role: awp::Profile,
    resume: Option<String>,
    session_file: PathBuf,
    run_dir: PathBuf,
}

fn read_json(path: &Path) -> Result<Value, a4aa::AdapterError> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| failure("audit_input_unreadable", "run/load"))?;
    serde_json::from_str(&raw).map_err(|_| failure("audit_input_invalid", "run/load"))
}

/// The review date stamped into a fresh conversation: UTC civil date, the
/// same convention `documents::today` writes into request documents.
fn review_date() -> String {
    jiff::Zoned::now()
        .with_time_zone(jiff::tz::TimeZone::UTC)
        .date()
        .to_string()
}

/// Derive the request from `--contract <path> --run <dir>`: the checker's
/// payload carries contract, registry, policy and installation; the run
/// directory carries scope, session and verdict state.
fn request_from(args: &[String]) -> Result<Request, a4aa::AdapterError> {
    let flag = |name: &str| -> Result<PathBuf, a4aa::AdapterError> {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| PathBuf::from(&pair[1]))
            .ok_or_else(|| failure("audit_args_invalid", "run/args"))
    };
    let contract_path = flag("--contract")?;
    let contract_dir = if contract_path.is_dir() {
        contract_path.clone()
    } else {
        contract_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let run_dir = flag("--run")?;
    let contract = read_json(&contract_dir.join("contract.json"))?;
    let installation = read_json(&contract_dir.join("installation.json"))?;
    let scope = read_json(&run_dir.join("scope.json"))?;
    let runtime = &scope["runtime"];
    let session_file = run_dir.join("audit-session.json");
    let resume = read_json(&session_file)
        .ok()
        .and_then(|saved| saved["session_id"].as_str().map(str::to_string));
    let has_report = run_dir.join("report.json").exists();
    let full = scope["mode"].as_str() == Some("full-service");
    let task = if resume.is_some() && has_report {
        "The final review verdict has already been submitted and is preserved. \
         Finish this resumed conversation without submitting another verdict or \
         repeating the review. The publication gate will validate the stored verdict."
            .to_string()
    } else if resume.is_some() {
        "Continue this same review from its preserved conversation and draft. \
         Correct the outstanding report fields; reuse evidence and do not restart the audit."
            .to_string()
    } else if full {
        contract["task_full_service"]
            .as_str()
            .unwrap_or_else(|| contract["task"].as_str().unwrap_or(""))
            .to_string()
    } else {
        contract["task"].as_str().unwrap_or("").to_string()
    };
    // The review date is fresh-conversation context; a resumed session
    // already carries it, so only the bare directive goes again.
    let prompt = if resume.is_some() {
        task
    } else {
        format!("Review date (UTC): {}\n\n{}", review_date(), task)
    };
    // The checker's one tool surface is the review server itself, fired
    // per run so it learns its contract and run directory from the gate.
    let review = installation["review"].as_str().unwrap_or("gitvault-review");
    let tool_server = json!({
        "type": "stdio",
        "name": "gitvault-audit",
        "command": review,
        "args": [
            "serve",
            "--contract",
            contract_dir.join("contract.json").to_string_lossy(),
            "--run",
            run_dir.to_string_lossy(),
        ],
        "env": [],
    });
    let policy = std::fs::read_to_string(contract_dir.join("policy.md"))
        .map_err(|_| failure("audit_input_unreadable", "run/load"))?;
    let role: awp::Profile = serde_json::from_value(json!({
        "id": contract["name"],
        "name": contract["title"],
        "revision": installation["synced"]["tag"].as_str(),
        "agent": runtime["harness"],
        "model": runtime["model"],
        "models": runtime.get("models").cloned().unwrap_or_else(|| json!([])),
        "windows": runtime.get("windows").cloned().unwrap_or_else(|| json!([])),
        "retry": runtime.get("retry").cloned().unwrap_or(Value::Null),
        "effort": runtime.get("effort").cloned().unwrap_or(Value::Null),
        "permission": "read-only",
        "instructions": policy,
        "mcpServers": [tool_server],
        "extensions": {"provider": runtime["provider"]},
    }))
    .map_err(|_| failure("audit_role_invalid", "profile/build"))?;
    Ok(Request {
        document: contract_dir.join("registry.json"),
        prompt,
        role,
        resume,
        session_file,
        run_dir,
    })
}

/// The audit is read-only: the only calls a permission prompt may approve
/// are the checker's own `gitvault-audit` evidence and verdict tools — the
/// tool surface the role itself declares. Every other prompt is cancelled,
/// never approved on the operator's behalf.
struct AuditPermissions;

#[async_trait::async_trait]
impl PermissionHandler for AuditPermissions {
    async fn decide(&self, prompt: PermissionPrompt) -> PermissionDecision {
        let audit_tool = prompt.title.contains("gitvault-audit")
            || prompt.raw.to_string().contains("gitvault-audit");
        if !audit_tool {
            return PermissionDecision::Cancelled;
        }
        prompt
            .options
            .iter()
            .find(|(_, _, kind)| kind.starts_with("allow"))
            .map(|(id, _, _)| PermissionDecision::Selected(id.clone()))
            .unwrap_or(PermissionDecision::Cancelled)
    }
}

/// Secret references the registry may declare. `devin-api-key` supplies the
/// fallback agent's ACP credential: an explicit `DEVIN_API_KEY` in the
/// host's environment wins; otherwise the Devin CLI's own credential store
/// supplies the key this host then presents explicitly through the
/// `authenticate` handshake. Nothing is read until a lane asks.
struct AuditSecrets;

#[async_trait::async_trait]
impl a4aa::SecretResolver for AuditSecrets {
    async fn resolve(&self, reference: &str) -> Option<String> {
        if reference != "devin-api-key" {
            return None;
        }
        if let Some(key) = std::env::var("DEVIN_API_KEY")
            .ok()
            .filter(|value| !value.is_empty())
        {
            return Some(key);
        }
        let path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)?
            .join(".local/share/devin/credentials.toml");
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|line| {
                let (key, value) = line.trim().split_once('=')?;
                (key.trim() == "windsurf_api_key")
                    .then(|| value.trim().trim_matches('"').to_owned())
                    .filter(|value| !value.is_empty())
            })
    }
}

fn save_session(path: &Path, id: &str) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", json!({"session_id":id}))
}

async fn run(request: Request) -> a4aa::Result<Value> {
    let role = &request.role;
    // AwP models general virtual agents. This publication gate admits only
    // audit roles: executable, environment and tool surface stay gate-owned —
    // the single MCP server the role carries is the one the engine projected.
    if role.agent != "opencode"
        || role.permission.as_deref() != Some("read-only")
        || role.extensions.get("provider") != Some(&json!("opencode"))
        || !role.env.is_empty()
        || role.cwd.is_some()
        || role.mechanisms.is_some()
        || role
            .effort
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || !role
            .mcp_servers
            .iter()
            .all(|server| server["name"] == "gitvault-audit")
    {
        return Err(failure("audit_role_not_admitted", "profile/resolve"));
    }
    // The role's model chain — primary plus same-agent fallbacks — is
    // restricted to the free OpenCode catalog.
    let chain_models = std::iter::once(role.model.as_deref().unwrap_or(""))
        .chain(role.models.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if chain_models
        .iter()
        .any(|model| model.is_empty() || !model.starts_with("opencode/"))
    {
        return Err(failure("audit_role_model_not_free", "profile/resolve"));
    }
    if role
        .instructions
        .as_deref()
        .is_none_or(|text| text.trim().is_empty())
    {
        return Err(failure(
            "audit_role_instructions_missing",
            "profile/resolve",
        ));
    }
    let document = std::fs::read_to_string(&request.document)
        .map_err(|_| failure("audit_document_unreadable", "registry/load"))?;
    let mut registry = awp::Registry::from_json(&document)?;
    let fallbacks: Vec<String> = registry
        .binding("audit")
        .map(|binding| binding.fallbacks().to_vec())
        .unwrap_or_default();
    let mut patch = role.to_patch();
    // `read-only` is the gate's admission posture — enforced by the declared
    // spec's fail-closed config and DenyAll — not an ACP session selector.
    // OpenCode advertises no permissions config option, so the field stays
    // out of session establishment.
    patch.permission = None;
    let mut overlay = awp::RegistryDocument::default();
    overlay.profiles.insert(role.id.clone(), patch);
    // Fallback candidates run the same role under a different agent: they
    // inherit persona, policy and the tool server, but keep their declared
    // agent and model catalog.
    for fallback in &fallbacks {
        overlay.profiles.insert(
            fallback.clone(),
            awp::ProfilePatch {
                name: Some(role.name.clone()),
                instructions: role.instructions.clone(),
                mcp_servers: Some(role.mcp_servers.clone()),
                ..Default::default()
            },
        );
    }
    registry.apply(overlay)?;
    let candidates: Vec<_> = registry
        .resolve_chain("audit")?
        .into_iter()
        .map(|agent| {
            agent
                .permission(Arc::new(AuditPermissions))
                .secrets(Arc::new(AuditSecrets))
        })
        .collect();
    // Every declared candidate must be an audit-admissible protocol agent:
    // the primary names this role; fallbacks may back a different harness
    // but never widen the admitted agent set. Both protocol lanes the
    // registry may declare — the native server and the ACP bridge — are
    // admissible; every other surface stays refused.
    for (index, agent) in candidates.iter().enumerate() {
        let profile = agent.profile();
        let admitted = match profile.agent.as_str() {
            "opencode" => profile
                .model_chain()
                .iter()
                .all(|model| model.starts_with("opencode/")),
            "devin" => profile.model.is_some(),
            _ => false,
        };
        if !matches!(agent.lane_kind(), awp::LaneKind::Acp | awp::LaneKind::Serve)
            || !admitted
            || (index == 0 && profile.id != role.id)
            || (index > 0 && !fallbacks.contains(&profile.id))
        {
            return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
        }
    }
    let identity = json!({"id":role.id,"revision":role.revision,
                          "principal":role.principal_id()});
    let (events, mut stream) = tokio::sync::mpsc::unbounded_channel();
    // Streamed text rides stderr for operator visibility; stdout is the
    // result document only.
    tokio::spawn(async move {
        while let Some(event) = stream.recv().await {
            if let AgentEvent::MessageChunk { text } = event {
                eprint!("{text}");
            }
        }
    });
    // Level-2 fallback: candidates are tried in declared order; a candidate
    // that cannot establish a session or finish the turn yields to the next.
    // Level-1 (same-agent model chain) lives inside each VirtualSession.
    let candidate_ids: Vec<String> = candidates
        .iter()
        .map(|agent| agent.profile().id.clone())
        .collect();
    let mut last_error = None;
    let mut attempts_log: Vec<Value> = Vec::new();
    for (index, agent) in candidates.iter().enumerate() {
        // A stale resume id must not strand the primary: retry once fresh
        // before advancing to the next candidate.
        let attempts: Vec<Option<String>> = match (index == 0, &request.resume) {
            (true, Some(resume)) => vec![Some(resume.clone()), None],
            _ => vec![None],
        };
        let mut opened = None;
        for resume in attempts {
            match agent
                .open_session(
                    SessionRequest {
                        cwd: Some(request.run_dir.clone()),
                        resume: resume.clone(),
                        ..Default::default()
                    },
                    events.clone(),
                )
                .await
            {
                Ok(session) => {
                    opened = Some((session, resume));
                    break;
                }
                Err(error) => {
                    attempts_log.push(json!({"profile":agent.profile().id,
                        "code":error.code,"stage":error.stage}));
                    last_error = Some(error);
                }
            }
        }
        let Some((session, resumed)) = opened else {
            continue;
        };
        let id = session.session_id().await;
        if id.is_empty() {
            last_error = Some(failure("audit_session_id_missing", "audit/open"));
            let _ = session.close().await;
            continue;
        }
        save_session(&request.session_file, &id)
            .map_err(|_| failure("audit_session_save_failed", "audit/open"))?;
        let outcome = {
            let turn = async {
                let prompt = TurnRequest {
                    text: request.prompt.clone(),
                    model: None,
                    effort: None,
                };
                // A resumed session already carries the role's policy; a
                // fresh one — primary or fallback — composes instructions in
                // under the profile's FirstTurn mode.
                if resumed.is_some() {
                    session.prompt_direct(prompt).await
                } else {
                    session.prompt_with(prompt).await
                }
            };
            tokio::pin!(turn);
            tokio::select! {
                outcome = &mut turn => outcome,
                _ = cancelled() => { session.cancel().await?; turn.await }
            }
        };
        let served = json!({
            "profile": session.profile().id,
            "agent": agent.profile().agent,
            "model": session.active_model(),
        });
        session.close().await?;
        match outcome {
            Ok(outcome) => {
                // The ACP end-turn usage field, reported verbatim; an agent
                // that answers without counters settles as null and the gate
                // refuses the receipt.
                let usage = outcome.usage.as_ref().map(|usage| {
                    json!({
                        "input_tokens": usage.input.unwrap_or(0),
                        "output_tokens": usage.output.unwrap_or(0),
                        "cache_read_tokens": usage.cached_input.unwrap_or(0),
                        "cache_write_tokens": usage.cached_write.unwrap_or(0),
                    })
                });
                return Ok(json!({"completed":outcome.stop_reason=="end_turn",
                          "stop_reason":outcome.stop_reason, "usage":usage,
                          "profile":identity, "served":served}));
            }
            Err(error) => {
                attempts_log.push(json!({"profile":agent.profile().id,
                    "code":error.code,"stage":error.stage}));
                last_error = Some(error);
            }
        }
    }
    // Quota recovery: when the role declares a retry policy, the earliest
    // eligible instant for the next attempt rides the failure detail — the
    // orchestrator decides whether to wake on it.
    let retry_at = role.retry.as_ref().and_then(|policy| {
        policy
            .wakeup(&jiff::Zoned::now(), None)
            .map(|when| when.to_string())
    });
    Err(last_error
        .map(|error| {
            error.with_detail(
                json!({"candidates":candidate_ids,"attempts":attempts_log,
                       "retryAt":retry_at})
                .to_string(),
            )
        })
        .unwrap_or_else(|| failure("audit_chain_empty", "registry/resolve")))
}

fn failure(code: &'static str, stage: &'static str) -> a4aa::AdapterError {
    a4aa::AdapterError::permanent(code, stage)
}

async fn cancelled() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install termination handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match request_from(&args) {
        Ok(request) => request,
        Err(error) => {
            eprintln!(
                "invalid audit-agent request: {} {}",
                error.code,
                error.detail.as_deref().unwrap_or("")
            );
            std::process::exit(2);
        }
    };
    match run(request).await {
        Ok(result) => println!("{result}"),
        Err(error) => {
            println!(
                "{}",
                json!({"completed":false,"failure":{
                "code":error.code,"stage":error.stage,"retryable":error.retryable,
                "uncertain_effect":error.uncertain_effect,"detail":error.detail}})
            );
            std::process::exit(1);
        }
    }
}
