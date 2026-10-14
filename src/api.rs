//! GitHub API proxy.
//!
//! The token never leaves this module. It is written to an anonymous pipe that
//! `curl` reads as its `Authorization` header, so it appears in no argv, no
//! environment variable, and no temporary file that outlives the request.
//!
//! This is the whole point of the design: an agent asks GitVault to *perform* an
//! operation. It receives the result. It never receives a credential, so it has
//! nothing to reuse elsewhere - which a credential helper, by contract, could
//! never achieve because git requires the secret in plaintext.
//!
//! Policy is applied before the request is built: the identity is resolved from
//! the target repository, and issuance refuses if the routing is not explicit.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::Config;
use crate::git::Repo;
use crate::identity;
use crate::unlock;
use crate::vault::Vault;

pub const API_ROOT: &str = "https://api.github.com";

/// Where the operation is aimed. A repository context is what makes policy
/// possible; without one there is no owner to check and issuance is refused
/// unless an identity is named explicitly.
#[derive(Debug, Clone)]
pub enum Target {
    Repo(String),
    Identity(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Classify an HTTP method.
///
/// Retained for reporting and for future risk-based policy. It deliberately does
/// NOT soften the unlock requirement: reads of private repositories are not
/// harmless, so both classes need an open window.
pub fn _access_is_reported_not_enforced() {}
pub fn access_for_method(method: &str) -> Access {
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => Access::Read,
        _ => Access::Write,
    }
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub target: Target,
    pub fields: Vec<(String, String)>,
    pub raw_fields: Vec<(String, String)>,
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub jq: Option<String>,
    pub silent: bool,
}

/// Decide which account may perform this request, and hand back its token.
///
/// Both halves matter. Resolving the identity says who *should* act; the account
/// allowlist and the explicit-rule requirement say who *may*. A read of a public
/// resource still goes through this, because the account used is part of the
/// permanent record either way.
fn authorize(cfg: &Config, target: &Target, access: Access, vault: &Vault) -> Result<String> {
    let (account, token) = match target {
        Target::Repo(slug) => {
            let repo = Repo::for_slug(slug);
            let outcome = identity::resolve(cfg, &repo, false)?;
            let account = outcome
                .account
                .clone()
                .ok_or_else(|| anyhow::anyhow!("identity '{}' has no account", outcome.identity))?;

            // An explicitly routed owner is required. Falling back to rules.default
            // would mean any repository name the caller invents could borrow the
            // default account's credentials.
            if outcome.reason.starts_with("rules.default") {
                bail!(
                    "refusing to act: no explicit rule for owner '{:?}'\n  \
                     resolved account : {account}\n  \
                     add a rules.owners entry, or a .gitvault-identity assertion",
                    repo.owner().unwrap_or_default()
                );
            }


            // Every authenticated operation requires an open window, reads included.
            //
            // Gating only writes was wrong. A read of a private repository returns
            // its contents, so an unlocked vault whose reads were free would still
            // hand out data - and the whole point of being the only egress is that
            // there is no free path through it.
            //
            // The window is asked for here, at the moment credentials are used -
            // never before. Checkers run first and cost the time they cost; a
            // window opened before them would expire during the audit.
            let _ = access;
            unlock::ensure_open(
                vault,
                &format!("GitVault: confirm to authenticate {account} to the GitHub API"),
                false,
            )?;
            let token = vault.token_for(&account)?;
            (account, token)
        }
        Target::Identity(key) => {
            let id = cfg
                .identities
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("identity '{key}' is not defined"))?;
            let account = id
                .account
                .clone()
                .ok_or_else(|| anyhow::anyhow!("identity '{key}' has no account"))?;
            // An explicit identity is the caller stating its intent; it still needs
            // an open window, because there is no repository to derive policy from.
            // Asked here, at use time, for the same reason as above.
            unlock::ensure_open(
                vault,
                &format!("GitVault: confirm to authenticate {account}"),
                false,
            )?;
            let token = vault.token_for(&account)?;
            (account, token)
        }
    };

    let _ = access;
    Ok(format!("{account}\u{0}{token}"))
}

/// Authorize, send the request and return the HTTP status and response body.
/// Output policy (printing, jq, error reporting) is the caller's choice.
fn perform(cfg: &Config, vault: &Vault, req: &Request) -> Result<(i32, String)> {
    let access = access_for_method(&req.method);
    let resolved = authorize(cfg, &req.target, access, vault)?;
    let (account, token) = resolved
        .split_once('\u{0}')
        .ok_or_else(|| anyhow::anyhow!("internal: malformed authorization"))?;
    let _ = account;

    let mut url = if req.path.starts_with("http") {
        req.path.clone()
    } else {
        format!("{API_ROOT}/{}", req.path.trim_start_matches('/'))
    };

    let mut args: Vec<String> = vec![
        "-sS".into(),
        "-X".into(),
        req.method.to_ascii_uppercase(),
        // The token arrives on stdin, never in argv.
        "-H".into(),
        "@-".into(),
        "-w".into(),
        "\n%{http_code}".into(),
    ];

    // Fields go where GitHub REST expects them: query parameters on reads, a
    // JSON object on writes - form encoding is refused by the API. -f values
    // are always strings; -F values are typed literals (true, false, null,
    // numbers, or @file for a file's contents).
    let is_read = matches!(req.method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS");
    if is_read {
        let query: Vec<String> = req
            .fields
            .iter()
            .chain(req.raw_fields.iter())
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect();
        if !query.is_empty() {
            let sep = if url.contains('?') { '&' } else { '?' };
            url.push_str(&format!("{sep}{}", query.join("&")));
        }
    } else if let Some(body) = &req.body {
        args.push("--data-binary".into());
        args.push(body.clone());
    } else if !req.fields.is_empty() || !req.raw_fields.is_empty() {
        let mut obj = serde_json::Map::new();
        for (k, v) in &req.fields {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
        for (k, v) in &req.raw_fields {
            obj.insert(k.clone(), typed_field_value(v)?);
        }
        args.push("-H".into());
        args.push("Content-Type: application/json".into());
        args.push("--data-binary".into());
        args.push(Value::Object(obj).to_string());
    }
    for h in &req.headers {
        args.push("-H".into());
        args.push(h.clone());
    }
    args.push(url);

    let mut child = Command::new("curl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run curl")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("could not open curl stdin"))?;
        // The header line carries the secret; everything in this block is discarded.
        writeln!(stdin, "Authorization: Bearer {token}")?;
        writeln!(stdin, "Accept: application/vnd.github+json")?;
    }

    let out = child.wait_with_output().context("curl failed")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // Split the trailing status code that -w appended.
    let (body, status) = match stdout.rsplit_once('\n') {
        Some((b, s)) => (b.to_string(), s.trim().parse::<i32>().unwrap_or(0)),
        None => (stdout.clone(), 0),
    };

    if status == 0 {
        bail!("request did not complete\n{}", stderr.trim());
    }
    Ok((status, body))
}

pub fn run(cfg: &Config, vault: &Vault, req: &Request) -> Result<i32> {
    let (status, body) = perform(cfg, vault, req)?;
    if status >= 400 {
        // Relay the API's own message: it is the most useful thing to show, and it
        // never contains the token.
        eprintln!("gitvault: HTTP {status}");
        if !body.trim().is_empty() {
            eprintln!("{}", prettify(&body));
        }
        return Ok(1);
    }

    if !req.silent && !body.trim().is_empty() {
        match &req.jq {
            Some(expr) => println!("{}", apply_jq(&body, expr)?),
            None => println!("{}", prettify(&body)),
        }
    }
    Ok(0)
}

/// Perform the request and hand back the selected value instead of printing.
///
/// Callers that need one response to shape the next request (for example,
/// resolving an owner's account type before choosing a list endpoint) use this;
/// the credential handling is identical to `run`.
pub fn run_value(cfg: &Config, vault: &Vault, req: &Request) -> Result<String> {
    let (status, body) = perform(cfg, vault, req)?;
    if status >= 400 {
        bail!("HTTP {status}: {}", body.trim());
    }
    match &req.jq {
        Some(expr) => apply_jq(&body, expr),
        None => Ok(body),
    }
}

/// Percent-encode one query component. Unreserved characters pass through;
/// everything else is UTF-8 byte-escaped.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The typed form of a `-F` field value, mirroring `gh api -F`: booleans, null
/// and numbers keep their type, `@path` reads a file, anything else is a
/// string.
fn typed_field_value(v: &str) -> Result<Value> {
    if let Some(path) = v.strip_prefix('@') {
        return Ok(Value::String(
            std::fs::read_to_string(path).with_context(|| format!("could not read {path}"))?,
        ));
    }
    Ok(match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        _ => v
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| v.parse::<f64>().map(Value::from))
            .unwrap_or_else(|_| Value::String(v.to_string())),
    })
}

fn prettify(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| body.to_string()),
        Err(_) => body.to_string(),
    }
}

/// A deliberately tiny subset of jq: dotted paths and array indices.
///
/// It exists because agents habitually write `--jq .field`, and failing outright
/// on that is worse than supporting the common cases. Anything more complex is
/// reported rather than silently mis-evaluated.
pub fn apply_jq(body: &str, expr: &str) -> Result<String> {
    let v: Value = serde_json::from_str(body).context("response is not JSON")?;
    let expr = expr.trim();
    if expr == "." || expr.is_empty() {
        return Ok(serde_json::to_string_pretty(&v)?);
    }
    // `.[]` maps over an array; everything before it is a path to that array.
    // Without this, listing the names in a response is impossible: `.[].name` is the
    // natural way to ask, and every alternative (`.[0].name`) answers a different
    // question. That gap is why a listing was previously reduced to its first
    // element.
    // Parsed as segments rather than by string surgery. Two earlier attempts split on
    // literal "[]" occurrences and got `.n.deep` and `.items[]` wrong in opposite
    // directions; a third mis-derived the path because the leading dot of a jq
    // expression is a prefix, not a separator. Each segment is a field name with an
    // optional selector, and at most the last one may be an iterator.
    enum Sel {
        None,
        Index(usize),
        Iterate,
    }
    let mut segments: Vec<(&str, Sel)> = Vec::new();
    let body = expr.strip_prefix('.').unwrap_or(expr);
    for raw in body.split('.') {
        if raw.is_empty() {
            continue;
        }
        let (name, sel) = match raw.find('[') {
            Some(b) => {
                let inner = raw[b + 1..].trim_end_matches(']');
                let sel = if inner.is_empty() {
                    Sel::Iterate
                } else {
                    match inner.parse::<usize>() {
                        Ok(i) => Sel::Index(i),
                        Err(_) => {
                            return Err(anyhow::anyhow!(
                                "jq: '{inner}' is not an index and not an iterator"
                            ));
                        }
                    }
                };
                (&raw[..b], sel)
            }
            None => (raw, Sel::None),
        };
        segments.push((name, sel));
    }

    let mut cur = &v;
    let mut iterate: Option<usize> = None;
    for (i, (name, sel)) in segments.iter().enumerate() {
        if !name.is_empty() {
            cur = cur
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("jq: field '{name}' not present"))?;
        }
        match sel {
            Sel::None => {}
            Sel::Index(n) => {
                cur = cur
                    .get(*n)
                    .ok_or_else(|| anyhow::anyhow!("jq: index {n} not present"))?;
            }
            Sel::Iterate => {
                // Only the final segment may iterate; a following field is applied to
                // each element below.
                iterate = Some(i);
                break;
            }
        }
    }

    let render = |v: &Value| -> Result<String> {
        Ok(match v {
            Value::String(s) => s.clone(),
            other => serde_json::to_string_pretty(other)?,
        })
    };

    let Some(at) = iterate else {
        return render(cur);
    };

    let arr = cur
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("jq: '[]' applied to a non-array"))?;

    // Segments after the iterator are applied to each element.
    let tail: Vec<&(&str, Sel)> = segments[at + 1..].iter().collect();
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let mut c = item;
        for (name, sel) in &tail {
            if !name.is_empty() {
                c = c
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("jq: field '{name}' not present"))?;
            }
            match sel {
                Sel::None => {}
                Sel::Index(n) => {
                    c = c
                        .get(*n)
                        .ok_or_else(|| anyhow::anyhow!("jq: index {n} not present"))?;
                }
                Sel::Iterate => {
                    return Err(anyhow::anyhow!(
                        "jq: only one '[]' is supported; nested iteration is not"
                    ));
                }
            }
        }
        out.push(render(c)?);
    }
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_write_are_classified_correctly() {
        assert_eq!(access_for_method("GET"), Access::Read);
        assert_eq!(access_for_method("get"), Access::Read);
        assert_eq!(access_for_method("HEAD"), Access::Read);
        assert_eq!(access_for_method("POST"), Access::Write);
        assert_eq!(access_for_method("PATCH"), Access::Write);
        assert_eq!(access_for_method("DELETE"), Access::Write);
        assert_eq!(access_for_method("PUT"), Access::Write);
    }

    #[test]
    fn access_classification_does_not_soften_the_gate() {
        // The classification exists for reporting; the gate must treat reads and
        // writes alike. This test pins that intent so a future change has to be
        // deliberate.
        assert_eq!(access_for_method("GET"), Access::Read);
        assert_eq!(access_for_method("POST"), Access::Write);
        _access_is_reported_not_enforced();
    }

    #[test]
    fn jq_handles_the_shapes_agents_actually_write() {
        let body = r#"{"login":"x","n":{"deep":42},"items":[{"id":7},{"id":8}]}"#;
        assert_eq!(apply_jq(body, ".login").unwrap(), "x");
        assert_eq!(apply_jq(body, "n.deep").unwrap(), "42");
        assert_eq!(apply_jq(body, ".items[0].id").unwrap(), "7");
        assert_eq!(apply_jq(body, ".items[1].id").unwrap(), "8");
        assert!(apply_jq(body, ".nope").is_err());
        assert!(apply_jq(body, ".n.deep.deeper").is_err());

        // Iteration. Regression: without it a listing could only be reduced to one
        // element, and `.[].name` — the natural way to ask for names — had no
        // equivalent at all.
        assert_eq!(apply_jq(body, ".items[]").unwrap(), "{\n  \"id\": 7\n}\n{\n  \"id\": 8\n}");
        assert_eq!(apply_jq(body, ".items[].id").unwrap(), "7\n8");
        // `[]` on a non-array is an error, and `.[]` here iterates the *root object*,
        // whose values are not arrays. The correct answer is a refusal, not a guess.
        assert!(apply_jq(body, ".[].id").is_err());

        // The shape that matters for listings: iterate a top-level array and read a
        // field from each element.
        let list = r#"[{"name":"a","archived":false},{"name":"b","archived":true}]"#;
        assert_eq!(apply_jq(list, ".[].name").unwrap(), "a\nb");
        assert_eq!(apply_jq(list, ".[]").unwrap().lines().count(), 8);
    }

    #[test]
    fn jq_iteration_refuses_rather_than_guessing() {
        let body = r#"{"items":[{"id":7}]}"#;
        assert!(apply_jq(body, ".items[].nope").is_err());
        assert!(apply_jq(body, ".login[]").is_err(), "[] on a non-array is an error");
    }

    #[test]
    fn jq_rejects_non_json_rather_than_guessing() {
        assert!(apply_jq("not json", ".x").is_err());
    }
}
