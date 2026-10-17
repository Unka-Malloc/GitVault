//! OpenCode audit host. The checker declares its agent and binding in an AwP
//! registry document (`registry.json`, written by the installer); the engine
//! projects the synced role — policy, model and the checker's one MCP tool
//! server — onto it at review time. AwP owns resolution, materialization and
//! instruction composition; A4AA owns the lane and process lifetime. This
//! host contributes only the gate's admission rules, the fail-closed
//! permission handler and the verdict counters the gate persists.
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use a4aa::proto::acp::{PermissionDecision, PermissionPrompt};
use a4aa::{AgentEvent, PermissionHandler, SessionRequest, TurnRequest};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// The installed AwP registry document declaring the audit agent and the
    /// `audit` binding.
    document: String,
    prompt: String,
    /// The engine-projected role: identity, policy, model and the review's
    /// one MCP tool server.
    role: awp::Profile,
    resume: Option<String>,
    session_file: String,
    run_dir: String,
}

/// The audit is read-only and every needed capability is denied in the
/// declared spec's OpenCode config already; anything that still reaches a
/// permission prompt is refused, never approved on the operator's behalf.
struct DenyAll;

#[async_trait::async_trait]
impl PermissionHandler for DenyAll {
    async fn decide(&self, _prompt: PermissionPrompt) -> PermissionDecision {
        PermissionDecision::Cancelled
    }
}

fn save_session(path: &str, id: &str) -> io::Result<()> {
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
        .map(|agent| agent.permission(Arc::new(DenyAll)))
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
                        cwd: Some(Path::new(&request.run_dir).to_owned()),
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
    let mut input = String::new();
    let request = io::stdin()
        .read_to_string(&mut input)
        .ok()
        .and_then(|_| serde_json::from_str::<Request>(&input).ok());
    let Some(request) = request else {
        eprintln!("invalid audit-agent request");
        std::process::exit(2);
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
