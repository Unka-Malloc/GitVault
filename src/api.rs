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
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::Config;
use crate::git::Repo;
use crate::identity;
use crate::unlock;
use crate::vault::Vault;

pub const API_ROOT: &str = "https://api.github.com";

/// The path part of a request with the API origin removed and the query and
/// fragment dropped. Absolute URLs are accepted only on the API origin: the
/// account token rides in the Authorization header of whatever the request
/// resolves to, so a caller-chosen host is refused before a credential is read.
fn relative_api_path(path: &str) -> Result<&str> {
    let rest = if let Some(rest) = path.strip_prefix(API_ROOT) {
        if !(rest.is_empty() || rest.starts_with('/')) {
            // api.github.com.evil.example and similar prefix look-alikes.
            bail!("refusing an absolute URL outside the API origin: {path}");
        }
        rest
    } else {
        if path.contains("://") {
            bail!("refusing an absolute URL outside the API origin: {path}");
        }
        path
    };
    Ok(rest
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches('/'))
}

/// Decode percent escapes in a path. A malformed escape is not a path this
/// broker will send: the caller gets a refusal rather than a guess.
fn percent_decode_path(path: &str) -> Option<String> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex(*bytes.get(i + 1)?)?;
            let lo = hex(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Decode the path portion of an API request after removing the origin, query
/// and fragment. `None` means the parser cannot produce the path the transport
/// will send, so a caller that authorizes writes refuses rather than matching
/// the raw spelling.
pub fn decoded_api_path(path: &str) -> Option<String> {
    let relative = relative_api_path(path).ok()?;
    percent_decode_path(relative)
}

/// Whether the raw path spells a separator with a percent escape. A decoded
/// `%2f` or `%5c` changes which segment a later check sees; the publication
/// surface refuses the whole request rather than guessing how the server will
/// split it.
pub fn has_encoded_separator(path: &str) -> bool {
    let Ok(relative) = relative_api_path(path) else {
        return true;
    };
    let lower = relative.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c")
}

/// Whether a request path is unsafe to resolve onto the API origin: a `.` or
/// `..` segment (including a percent-encoded spelling such as `%2e%2e`), an
/// encoded path separator, a backslash, a control character, or a percent
/// escape that survives one decode. `curl` and the API server normalize these
/// after the caller has chosen the path, so matching the raw text would let a
/// write reach a different route while the publication check saw a harmless
/// segment. A path this parser cannot decode is refused for the same reason.
pub fn path_has_traversal(path: &str) -> bool {
    // A single-encoded separator already changes the segment boundaries; a
    // doubled one leaves a `%2f` that a second decode would turn into one.
    if has_encoded_separator(path) {
        return true;
    }
    let Some(decoded) = decoded_api_path(path) else {
        return true;
    };
    // A decoded backslash is a path separator on some servers and a control
    // character has no business in a URL path; both are refused rather than
    // matched against a different spelling than the transport will use. A
    // remaining percent sign means the server's second decode could still
    // change the path, so the whole relative path is refused, not just the
    // surface tail.
    decoded.contains('%')
        || decoded.contains('\\')
        || decoded.chars().any(char::is_control)
        || decoded
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Resolve a request path to the URL the token will be sent to.
///
/// A relative path always lands under API_ROOT. An absolute URL is accepted
/// only when its origin is API_ROOT exactly - `https://api.github.com/...` -
/// because the account token rides in the Authorization header of whatever
/// this returns. Any other absolute URL, and any path with an unsafe segment,
/// is refused before a credential is read.
pub fn request_url(path: &str) -> Result<String> {
    let relative = relative_api_path(path)?;
    if path_has_traversal(relative) {
        bail!("refusing a path with an unsafe segment: {path}");
    }
    if path.strip_prefix(API_ROOT).is_some() {
        return Ok(path.to_string());
    }
    Ok(format!("{API_ROOT}/{}", path.trim_start_matches('/')))
}

/// Where the operation is aimed. A repository context is what makes policy
/// possible; without one there is no owner to check and issuance is refused
/// unless an identity is named explicitly.
#[derive(Debug, Clone)]
pub enum Target {
    Repo(String),
    Identity(String),
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
///
/// A token is a credential, so the routing table's certificate is re-checked
/// here, immediately before issuance. Audit surfaces deliberately parse the
/// table without its signature so the audit can run first; that must not let an
/// unsigned or tampered table spend the vault on a metadata read before the
/// gate refuses.
fn authorize(cfg: &Config, target: &Target, vault: &Vault) -> Result<String> {
    if let Some(path) = cfg.path.as_deref()
        && let crate::configsig::SigState::Invalid(reason) = crate::configsig::signature_state(path)
    {
        bail!(
            "refusing to spend a credential for an uncertified routing table\n  \
             {reason}\n  bless it: gitvault config sign"
        );
    }
    let token = match target {
        Target::Repo(slug) => {
            let repo = Repo::for_slug(slug);
            // Credentials follow the operator's rules, never repository content:
            // a `.gitvault-identity` file must not be able to pick which
            // account's token is used, so the assertion is not consulted here.
            let outcome = identity::resolve(cfg, &repo, true)?;
            let account = outcome
                .account
                .clone()
                .ok_or_else(|| anyhow::anyhow!("identity '{}' has no account", outcome.identity))?;

            // An explicitly routed owner is required. Falling back to rules.default
            // would mean any repository name the caller invents could borrow the
            // default account's credentials.
            if outcome.via_default {
                bail!(
                    "refusing to act: no explicit rule for owner '{:?}'\n  \
                     resolved account : {account}\n  \
                     add a rules.owners or rules.paths entry for this repository",
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
            // never at command start. A publication's semantic audit runs before
            // its publishing request; read-only boundary lookups (a merge's head
            // and base) happen earlier at the gate boundary, and a window opened
            // before a long audit would expire during it.
            unlock::ensure_open(
                vault,
                &format!("GitVault: confirm to authenticate {account} to the GitHub API"),
                false,
                None,
            )?;
            vault.token_for(&account)?
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
                None,
            )?;
            vault.token_for(&account)?
        }
    };

    Ok(token)
}

/// Authorize, send the request and return the HTTP status and response body.
/// Output policy (printing, jq, error reporting) is the caller's choice.
fn perform(cfg: &Config, vault: &Vault, req: &Request) -> Result<(i32, String)> {
    // The request path is validated before any credential is touched: an
    // absolute URL under a different origin would carry the account token to a
    // host the caller chose. Relative paths always resolve under API_ROOT.
    let mut url = request_url(&req.path)?;

    let token = authorize(cfg, &req.target, vault)?;

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
    let is_read = matches!(
        req.method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    );
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
        // The API only accepts JSON bodies, so an --input payload gets the
        // type declared unless the caller already named one - a manual -H
        // 'Content-Type: ...' would otherwise send the header twice.
        let content_type_set = req.headers.iter().any(|h| {
            h.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
        });
        if !content_type_set {
            args.push("-H".into());
            args.push("Content-Type: application/json".into());
        }
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

/// A deliberately tiny subset of jq: dotted paths, array indices, one `[]`
/// iterator, and comma-separated branches.
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
    // `a, b` evaluates each branch against the same input and emits one result
    // per line - the multi-select that create/read responses are asked for.
    let parts = split_top_level_commas(expr);
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            bail!("jq: empty branch in comma expression");
        }
        out.push(apply_jq_path(&v, part)?);
    }
    Ok(out.join("\n"))
}

/// Commas inside a `[]` selector belong to the selector, not the expression.
fn split_top_level_commas(expr: &str) -> Vec<&str> {
    let mut depth = 0i32;
    let mut last = 0usize;
    let mut out = Vec::new();
    for (i, c) in expr.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth <= 0 => {
                out.push(&expr[last..i]);
                last = i + 1;
            }
            _ => {}
        }
    }
    out.push(&expr[last..]);
    out
}

fn apply_jq_path(v: &Value, expr: &str) -> Result<String> {
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

    let mut cur = v;
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
    fn request_url_keeps_the_token_on_the_api_origin() {
        assert_eq!(request_url("user").unwrap(), "https://api.github.com/user");
        assert_eq!(
            request_url("/repos/a/b").unwrap(),
            "https://api.github.com/repos/a/b"
        );
        assert_eq!(
            request_url("https://api.github.com/user").unwrap(),
            "https://api.github.com/user"
        );
        for hostile in [
            "https://evil.example/user",
            "http://api.github.com/user",
            "https://api.github.com.evil.example/user",
            "https://api.github.com@evil.example/",
        ] {
            assert!(request_url(hostile).is_err(), "must refuse {hostile}");
        }
    }

    #[test]
    fn request_url_refuses_dot_segment_traversal() {
        for hostile in [
            "repos/o/r/../r/statuses/deadbeef",
            "repos/o/r/./statuses/deadbeef",
            "repos/o/r/%2e%2e/r/statuses/deadbeef",
            "repos/o/r/%2E%2E/r/git/refs",
            "repos/o/r/.%2e/r/releases",
            "repos/o/r/%2e%2e%2fr/statuses/deadbeef",
            "https://api.github.com/repos/o/r/../r/statuses/deadbeef",
            "repos/o/r/..%5Cr/statuses/deadbeef",
            "repos/o/r/%2/statuses/deadbeef",
        ] {
            assert!(request_url(hostile).is_err(), "must refuse {hostile}");
            assert!(path_has_traversal(hostile), "must detect {hostile}");
        }
        assert!(!path_has_traversal("repos/o/r/statuses/deadbeef"));
        assert!(!path_has_traversal("repos/o/r/contents/docs%20one/file.md"));
        assert_eq!(
            request_url("repos/o/r/contents/docs%20one/file.md").unwrap(),
            "https://api.github.com/repos/o/r/contents/docs%20one/file.md"
        );
    }

    #[test]
    fn decoded_paths_name_the_route_the_server_will_see() {
        assert_eq!(
            decoded_api_path("repos/o/r/%63ontents/src/lib.rs").as_deref(),
            Some("repos/o/r/contents/src/lib.rs")
        );
        assert_eq!(
            decoded_api_path("https://api.github.com/repos/o/r/%72eleases").as_deref(),
            Some("repos/o/r/releases")
        );
        assert_eq!(decoded_api_path("repos/o/r/%2"), None);
        assert!(has_encoded_separator("repos/o/r/contents%2Fsrc"));
        assert!(has_encoded_separator("repos/o/r/contents%5Csrc"));
        assert!(!has_encoded_separator(
            "repos/o/r/contents/docs%20one/file.md"
        ));
        // A single-encoded separator changes the route, and a doubled one
        // leaves `%2f` after one decode. Both are refused across the whole
        // path, not only in the surface tail: an owner/repo segment must not
        // be able to shift the /repos/{owner}/{repo} boundary.
        assert!(path_has_traversal("repos/o/r/contents%2Fsrc"));
        assert!(request_url("repos/o/r/contents%2Fsrc").is_err());
        assert!(path_has_traversal("repos/o%252fr/r/statuses/deadbeef"));
        assert!(path_has_traversal("repos/o/r%252fextra/statuses/deadbeef"));
        assert!(request_url("repos/o%252fr/r/statuses/deadbeef").is_err());
        assert!(request_url("repos/o/r%252fextra/statuses/deadbeef").is_err());
        // An ordinary escaped value that decodes to no separator stays valid.
        assert!(!path_has_traversal("repos/o/r/contents/docs%20one/file.md"));
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
        assert_eq!(
            apply_jq(body, ".items[]").unwrap(),
            "{\n  \"id\": 7\n}\n{\n  \"id\": 8\n}"
        );
        assert_eq!(apply_jq(body, ".items[].id").unwrap(), "7\n8");
        // `[]` on a non-array is an error, and `.[]` here iterates the *root object*,
        // whose values are not arrays. The correct answer is a refusal, not a guess.
        assert!(apply_jq(body, ".[].id").is_err());

        // Comma branches each evaluate against the same input - the multi-select
        // agents write when reading created resources (`.id, .enforcement`).
        assert_eq!(apply_jq(body, ".login, .n.deep").unwrap(), "x\n42");
        assert_eq!(apply_jq(body, ".items[].id, .login").unwrap(), "7\n8\nx");
        assert!(apply_jq(body, ".login, ").is_err(), "empty branch refuses");
        // A comma inside `[]` belongs to the selector, so it is never split and
        // still fails as an unsupported index - never silently two outputs.
        assert!(apply_jq(body, ".items[0,1].id").is_err());

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
        assert!(
            apply_jq(body, ".login[]").is_err(),
            "[] on a non-array is an error"
        );
    }

    #[test]
    fn jq_rejects_non_json_rather_than_guessing() {
        assert!(apply_jq("not json", ".x").is_err());
    }

    #[test]
    fn a_default_route_is_marked_so_the_gate_can_refuse_it() {
        // The vault would hold the default account's token, and the repository
        // matches no owner rule - so `rules.default` resolves the identity. A
        // fallback may not be a credential source: the outcome must say so
        // structurally, not through a display string the gate has to parse.
        use crate::config::{Identity, Rules};
        use std::collections::BTreeMap;

        let mut identities = BTreeMap::new();
        identities.insert(
            "personal".to_string(),
            Identity {
                name: "n".into(),
                email: "e@x".into(),
                account: Some("acct".to_string()),
                ssh_key: None,
                signing_key: None,
            },
        );
        let cfg = Config {
            identities,
            rules: Rules {
                owners: BTreeMap::new(),
                default: Some("personal".to_string()),
                ..Default::default()
            },
            audit_policy: None,
            record_dir: None,
            path: None,
        };
        let repo = Repo::for_test("/tmp/x", Some("git@github.com:Attacker/Repo.git"));
        let outcome = crate::identity::resolve(&cfg, &repo, false).unwrap();
        assert!(
            outcome.via_default,
            "an unrouted repository must not look routed"
        );
    }
}
