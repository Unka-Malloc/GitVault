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
/// Release assets are uploaded to a different host than the REST API; the
/// release response names it in `upload_url`. It is the only other origin a
/// token may be sent to.
pub const UPLOAD_ROOT: &str = "https://uploads.github.com";

/// The path part of a request with a sanctioned origin removed and the query
/// and fragment dropped. Absolute URLs are accepted only on the API and upload
/// origins: the account token rides in the Authorization header of whatever
/// the request resolves to, so a caller-chosen host is refused before a
/// credential is read.
fn relative_api_path(path: &str) -> Result<&str> {
    let mut absolute = None;
    for origin in [API_ROOT, UPLOAD_ROOT] {
        if let Some(rest) = path.strip_prefix(origin) {
            if !(rest.is_empty() || rest.starts_with('/')) {
                // api.github.com.evil.example and similar prefix look-alikes.
                bail!("refusing an absolute URL outside the sanctioned origins: {path}");
            }
            absolute = Some(rest);
            break;
        }
    }
    let rest = match absolute {
        Some(rest) => rest,
        None => {
            if path.contains("://") {
                bail!("refusing an absolute URL outside the sanctioned origins: {path}");
            }
            path
        }
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
        // curl glob metacharacters would let one classified path expand into
        // requests to other routes at the transport layer. The transport also
        // runs with --globoff; this keeps the ambiguity out of the path itself.
        || decoded.contains('{')
        || decoded.contains('}')
        || decoded.contains('[')
        || decoded.contains(']')
        || decoded
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Resolve a request path to the URL the token will be sent to.
///
/// A relative path always lands under API_ROOT. An absolute URL is accepted
/// only when its origin is a sanctioned one exactly - `https://api.github.com`
/// or `https://uploads.github.com` - because the account token rides in the
/// Authorization header of whatever this returns. Any other absolute URL, and
/// any path with an unsafe segment, is refused before a credential is read.
pub fn request_url(path: &str) -> Result<String> {
    let relative = relative_api_path(path)?;
    if path_has_traversal(relative) {
        bail!("refusing a path with an unsafe segment: {path}");
    }
    if [API_ROOT, UPLOAD_ROOT]
        .iter()
        .any(|origin| path.strip_prefix(origin).is_some())
    {
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
    /// A descriptor whose bytes we stream into the request body ourselves:
    /// curl reads a pipe, we write it while hashing, so the bytes on the
    /// wire are provably the bytes the digest was computed on. Mutually
    /// exclusive with `body`.
    pub body_stream: Option<std::fs::File>,
    /// Follow one redirect hop inside the broker: some read endpoints
    /// (Actions logs, archive downloads) answer 302 to a signed URL on a
    /// download host. The signed URL carries a download credential in its
    /// query, so it is fetched here - never printed - with a second,
    /// unauthenticated request restricted to the download-host allowlist.
    /// The account token exists only inside the first request's pipe.
    pub follow: bool,
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
    if let Some(path) = cfg.path.as_deref() {
        // The signature is checked against the bytes this `Config` was parsed
        // from, not a fresh read of the path: a file swapped between the gate
        // boundary and this credential moment must not launder stale routing
        // through a different signed copy. `data` is that same buffer, so a
        // current-file read that happens to verify is never what authorizes.
        let data =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let same_source = cfg
            .source_digest
            .map(|expected| {
                use sha2::Digest as _;
                let mut hasher = sha2::Sha256::new();
                hasher.update(&data);
                expected == <[u8; 32]>::from(hasher.finalize())
            })
            // A `Config` without a bound digest (a test fixture) cannot bind
            // a snapshot; fall back to the file check.
            .unwrap_or(true);
        anyhow::ensure!(
            same_source,
            "the routing table changed since it was parsed; refusing to spend \
             a credential on stale routing data - reload and retry"
        );
        if let crate::configsig::SigState::Invalid(reason) =
            crate::configsig::signature_state_for(path, &data)
        {
            bail!(
                "refusing to spend a credential for an uncertified routing table\n  \
                 {reason}\n  bless it: gitvault config sign"
            );
        }
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

/// The transport executable: the platform's own curl, checked against the same
/// root-owned / non-replaceable chain rule the audit engine must pass. A PATH
/// lookup would hand the vault token to whatever `curl` a writable directory
/// happens to name first.
#[cfg(unix)]
fn curl_program() -> Result<PathBuf> {
    let program = PathBuf::from("/usr/bin/curl");
    anyhow::ensure!(
        crate::configsig::executable_is_trusted(&program),
        "the transport executable {} is not trusted (root-owned, unwritable, \
         non-replaceable chain required)",
        program.display()
    );
    Ok(program)
}

#[cfg(not(unix))]
fn curl_program() -> Result<PathBuf> {
    Ok(PathBuf::from("curl"))
}

/// The host a redirect may point at. Log and archive downloads leave the
/// API origin for a signed URL on a download host - GitHub's own redirect
/// names one of these, and the second hop authenticates nothing itself.
/// Anything else refuses: the signed URL is never sent anywhere the
/// broker did not already sanction.
const REDIRECT_HOSTS: [&str; 4] = [
    "github.com",
    "githubusercontent.com",
    "amazonaws.com",
    "blob.core.windows.net",
];

/// Judge where a redirect goes. The signed URL carries a download
/// credential inside its query, so it is fetched and never echoed - a
/// refusal names the host, not the URL. `https` stays mandatory, userinfo
/// is refused, and the host must sit on the download allowlist.
fn signed_redirect_target(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .with_context(|| "a redirect must stay on https")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    anyhow::ensure!(
        !authority.contains('@'),
        "a redirect carrying userinfo is refused"
    );
    let host = authority
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    anyhow::ensure!(
        REDIRECT_HOSTS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}"))),
        "a redirect to '{host}' is not on the download allowlist"
    );
    Ok(url.to_string())
}

/// Fetch a redirect target with no credential at all: the signed URL is
/// self-authenticating, and sending the account token - or any header -
/// to a download host would hand a credential where none is needed.
///
/// The URL rides to curl inside an anonymous `-K -` config fed through a
/// private pipe, so it never appears in argv, the environment or a
/// diagnostic: a same-user process reading another process's arguments
/// cannot lift the download credential it encodes. Response headers reach
/// the broker through a second private descriptor (`-D /dev/fd/N`), so
/// the body stream is clean bytes all the way to the caller's stdout -
/// nothing holds the whole archive in memory, and no trailer parsing has
/// to guess where the download ended. Only the final response's body is
/// written to `sink`; an intermediate redirect's stub is drained and
/// dropped because its Location is read from the headers first.
///
/// Returns `(status, next_redirect)`.
#[cfg(unix)]
fn stream_signed_target(url: &str, sink: &mut dyn std::io::Write) -> Result<(i32, String)> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    anyhow::ensure!(
        !url.contains(['"', '\\', '\n', '\r']),
        "the redirect URL cannot be expressed in curl's config format"
    );
    // The response-header channel: curl writes `-D` output through an
    // inherited descriptor, so status and Location are read without
    // touching the body stream at all.
    let mut header_pipe = [0i32; 2];
    anyhow::ensure!(
        unsafe { libc::pipe(header_pipe.as_mut_ptr()) } == 0,
        "cannot create the redirect hop's header pipe: {}",
        std::io::Error::last_os_error()
    );
    let (mut header_read, header_write) = unsafe {
        (
            std::fs::File::from_raw_fd(header_pipe[0]),
            std::fs::File::from_raw_fd(header_pipe[1]),
        )
    };
    // CLOEXEC on our copy keeps the descriptor out of unrelated spawns;
    // the child's own pre_exec clears it after fork, so it is exactly this
    // request's curl that can write the headers it collects.
    let header_fd = header_write.as_raw_fd();
    anyhow::ensure!(
        unsafe { libc::fcntl(header_fd, libc::F_SETFD, libc::FD_CLOEXEC) } != -1,
        "cannot mark the header pipe close-on-exec"
    );
    let mut request = Command::new(curl_program()?);
    request
        .args([
            "-q",
            "-sS",
            "--globoff",
            "--proto",
            "=https",
            "-X",
            "GET",
            "-D",
            &format!("/dev/fd/{header_fd}"),
            "-K",
            "-",
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    use std::os::unix::process::CommandExt as _;
    unsafe {
        request.pre_exec(move || {
            if libc::fcntl(header_fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = request
        .spawn()
        .context("failed to run curl for the redirect hop")?;
    drop(header_write);
    use std::io::{Read as _, Write as _};
    child
        .stdin
        .take()
        .context("no stdin for the redirect hop")?
        .write_all(format!("url = \"{url}\"\n").as_bytes())
        .context("could not hand the signed URL to curl")?;
    // The head block ends at the first blank line - read exactly that
    // far, bounded, instead of waiting on the descriptor's EOF: curl keeps
    // the `-D` handle open for the whole transfer, so waiting for EOF
    // would deadlock against a body that fills its pipe before exit.
    let mut headers = Vec::new();
    {
        let mut byte = [0u8; 1];
        while headers.len() < 64 * 1024 && !headers.ends_with(b"\r\n\r\n") {
            match header_read.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => headers.push(byte[0]),
            }
        }
    }
    let (status, redirect) =
        parse_response_head(&headers).context("the download host sent no complete header block")?;
    if status >= 400 {
        // The error page's body still fills the stdout pipe - drain it
        // before waiting or the child parks mid-transfer and never exits.
        if let Some(mut body) = child.stdout.take() {
            std::io::copy(&mut body, &mut std::io::sink()).ok();
        }
        let out = child
            .wait_with_output()
            .context("the redirect hop did not finish")?;
        let detail = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("the download host refused ({status}): {}", detail.trim());
    }
    if (300..400).contains(&status) && !redirect.is_empty() {
        // An intermediate hop: its stub body is drained (curl blocks when
        // the pipe fills), never written to the caller.
        let mut body = child.stdout.take().expect("piped stdout");
        std::io::copy(&mut body, &mut std::io::sink()).ok();
        let out = child
            .wait_with_output()
            .context("the redirect hop did not finish")?;
        anyhow::ensure!(out.status.success(), "the redirect hop did not run");
        return Ok((status, redirect));
    }
    // The final hop: its body is the log or archive the caller asked for.
    // Pump it through with a fixed buffer - an archive of any size moves
    // with constant memory, and the bytes reach the sink unmangled.
    let mut body = child.stdout.take().expect("piped stdout");
    std::io::copy(&mut body, sink).context("could not stream the response body")?;
    let out = child
        .wait_with_output()
        .context("the redirect hop did not finish")?;
    anyhow::ensure!(out.status.success(), "the redirect hop did not run");
    Ok((status, String::new()))
}

/// Parse a complete HTTP response head (status + Location) out of the bytes
/// a `-D` dump handed us. The block must end at a CRLF blank line - that is
/// the bound that lets the caller stop reading while the transfer is still
/// streaming, instead of waiting for an EOF that only arrives at exit.
fn parse_response_head(raw: &[u8]) -> Option<(i32, String)> {
    let cut = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)?;
    let head = String::from_utf8_lossy(&raw[..cut]);
    let status = head
        .lines()
        .find_map(|line| {
            line.strip_prefix("HTTP/")
                .and_then(|rest| rest.split_whitespace().nth(1))
                .and_then(|code| code.parse::<i32>().ok())
        })
        .unwrap_or(0);
    let redirect = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("location")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    Some((status, redirect))
}

/// Redirect hops need descriptor passing that only unix provides; a follow
/// request there refuses before the first hop rather than after it.
#[cfg(not(unix))]
fn stream_signed_target(_url: &str, _sink: &mut dyn std::io::Write) -> Result<(i32, String)> {
    anyhow::bail!("--follow needs descriptor inheritance, which this platform lacks")
}

/// The trailer `-w` appends: body bytes, then a newline, the HTTP code,
/// another newline and `redirect_url` (empty when the response was not a
/// redirect). Split from the right so a binary body - a log archive is a
/// zip - stays intact.
fn split_transport_output(stdout: &[u8]) -> (Vec<u8>, i32, String) {
    let (head, redirect) = match stdout.iter().rposition(|b| *b == b'\n') {
        Some(at) => (
            &stdout[..at],
            String::from_utf8_lossy(&stdout[at + 1..]).to_string(),
        ),
        None => (stdout, String::new()),
    };
    let (body, status) = match head.iter().rposition(|b| *b == b'\n') {
        Some(at) => (
            head[..at].to_vec(),
            String::from_utf8_lossy(&head[at + 1..])
                .trim()
                .parse::<i32>()
                .unwrap_or(0),
        ),
        None => (head.to_vec(), 0),
    };
    (body, status, redirect.trim().to_string())
}

/// Authorize, send the request and return the HTTP status and response body.
/// Output policy (printing, jq, error reporting) is the caller's choice.
fn perform(
    cfg: &Config,
    vault: &Vault,
    req: &Request,
    sink: &mut dyn std::io::Write,
) -> Result<(i32, Vec<u8>, Option<String>)> {
    // Redirect following exists for the log/archive GETs it was built
    // for: a second hop cannot carry a different method's contract, and a
    // body that streams straight to the caller's stdout cannot be
    // re-shaped by a jq expression afterwards.
    anyhow::ensure!(
        !req.follow || req.method.eq_ignore_ascii_case("GET"),
        "--follow is only valid on GET requests"
    );
    anyhow::ensure!(
        !req.follow || req.jq.is_none(),
        "--follow streams raw response bytes; a jq selection cannot apply"
    );
    // The request path is validated before any credential is touched: an
    // absolute URL under a different origin would carry the account token to a
    // host the caller chose. Relative paths always resolve under API_ROOT.
    let mut url = request_url(&req.path)?;

    let token = authorize(cfg, &req.target, vault)?;

    // A streamed body is piped into curl: the read end becomes its
    // `--data-binary` source, the write end is where we feed and hash the
    // descriptor. Both ends are born close-on-exec: a child that inherited
    // its own copy of the writer would hold the pipe open after our last
    // write and wait on an EOF that can never arrive. The descriptors are
    // owned as Files from creation, so a spawn failure or early refusal
    // still closes them.
    #[cfg(unix)]
    let body_pipe: Option<(std::fs::File, std::fs::File)> = if req.body_stream.is_some() {
        use std::os::unix::io::FromRawFd as _;
        let mut fds = [0i32; 2];
        anyhow::ensure!(
            unsafe { libc::pipe(fds.as_mut_ptr()) } == 0,
            "cannot pipe the request body"
        );
        for fd in fds {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                anyhow::bail!("cannot mark the request-body pipe close-on-exec");
            }
        }
        Some(unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        })
    } else {
        None
    };
    #[cfg(unix)]
    let (pipe_read, pipe_write) = body_pipe
        .as_ref()
        .map(|(reader, writer)| {
            use std::os::unix::io::AsRawFd as _;
            (reader.as_raw_fd(), writer.as_raw_fd())
        })
        .unwrap_or((-1, -1));
    #[cfg(not(unix))]
    anyhow::ensure!(
        req.body_stream.is_none(),
        "a streamed request body is not supported on this platform"
    );

    let mut args: Vec<String> = vec![
        // First argument is `-q`: curl skips the user's curlrc entirely, so a
        // ~/.curlrc cannot weaken TLS, add redirects or set a proxy under the
        // broker's endpoint allowlist.
        "-q".into(),
        "-sS".into(),
        // One request carries one URL: curl's `{}`/`[]` globbing could expand
        // a single classified path into requests to routes the publication
        // check never saw (e.g. a `releases` write riding inside a read).
        "--globoff".into(),
        // The token may only ride HTTPS - no protocol downgrade, and no
        // redirect may carry it to another scheme either.
        "--proto".into(),
        "=https".into(),
        "--proto-redir".into(),
        "=https".into(),
        "-X".into(),
        req.method.to_ascii_uppercase(),
        // The token arrives on stdin, never in argv.
        "-H".into(),
        "@-".into(),
        "-w".into(),
        // The redirect URL lands in the trailer too: a logs/download
        // endpoint's 302 can then be followed inside the broker instead of
        // handing the caller an empty body and no way to reach the bytes.
        "\n%{http_code}\n%{redirect_url}".into(),
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
    } else if req.body.is_some() && req.body_stream.is_some() {
        bail!("a request cannot carry both an inline body and a streamed body");
    } else if req.body_stream.is_some() {
        // curl reads the pipe as the request body; we stream the descriptor
        // into it and hash every byte on its way to the wire. Octet-stream
        // is the fallback when the caller names no content type.
        let content_type_set = req.headers.iter().any(|h| {
            h.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
        });
        if !content_type_set {
            args.push("-H".into());
            args.push("Content-Type: application/octet-stream".into());
        }
        args.push("--data-binary".into());
        args.push(format!("@/dev/fd/{pipe_read}"));
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

    // The broker's transport is the system curl, never whatever `curl` a PATH
    // search finds: a shim in a user-writable directory would receive the
    // token. The executable must pass the same trust check the audit engine
    // does, and the child starts with an empty environment so CURL_* or
    // proxy variables cannot steer the request.
    let mut command = Command::new(curl_program()?);
    command
        .args(&args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    if req.body_stream.is_some() {
        // The child gets exactly the read descriptor and nothing else:
        // clearing its close-on-exec flag in pre-exec lets `/dev/fd/N`
        // survive the exec at the same number, and the write end is closed
        // explicitly so curl can never hold the pipe open past our last
        // write.
        use std::os::unix::process::CommandExt as _;
        let inherited = pipe_read;
        let writer = pipe_write;
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(inherited, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(writer);
                Ok(())
            });
        }
    }
    let mut child = command.spawn().context("failed to run curl")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("could not open curl stdin"))?;
        // The header line carries the secret; everything in this block is discarded.
        writeln!(stdin, "Authorization: Bearer {token}")?;
        writeln!(stdin, "Accept: application/vnd.github+json")?;
    }
    // curl reads `-H @-` until our end of stdin closes. A streamed body
    // cannot start flowing until curl is past that read, so our stdin handle
    // drops here rather than inside wait_with_output.
    drop(child.stdin.take());

    // The streamed body is written while curl reads it: every byte the wire
    // carries also passes the digest, so the hash describes what was sent,
    // not what a file contained at some earlier check.
    #[cfg(unix)]
    let sent_digest = if let Some(source) = req.body_stream.as_ref() {
        use sha2::Digest as _;
        use std::io::{Read as _, Write as _};
        let (reader, mut writer) = body_pipe.expect("a streamed request body always owns its pipe");
        // The parent's read end is never used - curl holds its own copy.
        drop(reader);
        let mut source = source;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let result = (|| -> Result<String> {
            loop {
                let read = source.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                writer.write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
            }
            Ok(hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect())
        })();
        // Closing the write end is how curl learns the body ended - even on
        // a stream failure, so the child cannot wait on a pipe we abandoned.
        drop(writer);
        match result {
            Ok(digest) => Some(digest),
            Err(why) => {
                let _ = child.wait_with_output();
                return Err(why.context("could not stream the request body"));
            }
        }
    } else {
        None
    };
    #[cfg(not(unix))]
    let sent_digest: Option<String> = None;

    let out = child.wait_with_output().context("curl failed")?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let (mut body, mut status, mut redirect) = split_transport_output(&out.stdout);

    if status == 0 {
        bail!("request did not complete\n{}", stderr.trim());
    }
    // The redirect hop: a 3xx answer the caller asked to follow is re-sent
    // by the broker itself against the signed download URL - the account
    // token exists only in this request's pipe and never in the second
    // hop, which carries no credential at all. The signed URL rides to
    // curl through a stdin config, so it is never in argv either. The
    // final hop's body streams straight to the caller's stdout through a
    // bounded pump, so a log archive of any size moves with constant
    // memory; the returned body stays empty for that path. At most four
    // hops, each judged against the download-host allowlist before it is
    // fetched.
    let mut hops = 0;
    while req.follow && hops < 4 && (300..400).contains(&status) && !redirect.is_empty() {
        let target = signed_redirect_target(&redirect)?;
        let (next_status, next_redirect) = stream_signed_target(&target, sink)?;
        sink.flush()?;
        status = next_status;
        redirect = next_redirect;
        body = Vec::new();
        hops += 1;
    }
    Ok((status, body, sent_digest))
}

pub fn run(cfg: &Config, vault: &Vault, req: &Request) -> Result<i32> {
    // A followed response streams to the caller's sink while it downloads:
    // --silent drains those bytes too, so a silent call never leaks a log
    // body to the terminal or a pipeline capture.
    let mut sink: Box<dyn std::io::Write> = if req.silent {
        Box::new(std::io::sink())
    } else {
        Box::new(std::io::stdout().lock())
    };
    let (status, body, _sent) = perform(cfg, vault, req, &mut sink)?;
    if status >= 400 {
        // Relay the API's own message: it is the most useful thing to show, and it
        // never contains the token.
        eprintln!("gitvault: HTTP {status}");
        let text = String::from_utf8_lossy(&body);
        if !text.trim().is_empty() {
            eprintln!("{}", prettify(&text));
        }
        return Ok(1);
    }

    if !req.silent && !body.is_empty() {
        match &req.jq {
            Some(expr) => println!("{}", apply_jq(&String::from_utf8_lossy(&body), expr)?),
            // A followed log download can be a zip or a gzip stream: only
            // a UTF-8 body goes through the JSON pretty-printer; binary
            // bytes are written raw so nothing is mangled.
            None => match String::from_utf8(body) {
                Ok(text) => println!("{}", prettify(&text)),
                Err(raw) => {
                    let raw = raw.into_bytes();
                    use std::io::Write as _;
                    std::io::stdout().write_all(&raw)?;
                }
            },
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
    let (status, body, _sent) = perform(cfg, vault, req, &mut std::io::sink())?;
    let body = String::from_utf8_lossy(&body).to_string();
    if status >= 400 {
        bail!("HTTP {status}: {}", body.trim());
    }
    match &req.jq {
        Some(expr) => apply_jq(&body, expr),
        None => Ok(body),
    }
}

/// Like `run_value`, but for a request whose body rides `body_stream`: the
/// caller also gets the digest of the exact bytes curl was fed, so an
/// upload can prove it carried the audited bytes rather than bytes a file
/// once held.
#[cfg(unix)]
pub fn run_value_streamed(cfg: &Config, vault: &Vault, req: &Request) -> Result<(String, String)> {
    anyhow::ensure!(
        req.body_stream.is_some(),
        "a streamed upload needs its source descriptor"
    );
    let (status, body, sent) = perform(cfg, vault, req, &mut std::io::sink())?;
    let body = String::from_utf8_lossy(&body).to_string();
    if status >= 400 {
        bail!("HTTP {status}: {}", body.trim());
    }
    let value = match &req.jq {
        Some(expr) => apply_jq(&body, expr)?,
        None => body,
    };
    Ok((value, sent.unwrap_or_default()))
}

/// Percent-encode one query component. Unreserved characters pass through;
/// everything else is UTF-8 byte-escaped.
pub(crate) fn percent_encode(s: &str) -> String {
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
    fn signed_redirect_targets_only_allowlisted_https_hosts() {
        // The shapes GitHub actually returns: Azure blob for log archives,
        // githubusercontent for media, S3 for older storage.
        for good in [
            "https://productionresultssa9.blob.core.windows.net/actions-results/abc/logs.zip?sig=SECRET",
            "https://objects.githubusercontent.com/github-production-release-asset/x.zip?X-Amz-Signature=SECRET",
            "https://github-cloud.s3.amazonaws.com/run/1/logs.zip?X-Amz-Signature=SECRET",
            "https://api.github.com/repos/o/r/zipball/main",
        ] {
            assert_eq!(
                signed_redirect_target(good).unwrap(),
                good,
                "must accept {good}"
            );
        }
        for bad in [
            // A non-https redirect would carry the signed URL in the clear.
            "http://objects.githubusercontent.com/x.zip",
            // A host the broker never sanctioned must not receive the URL.
            "https://evil.example/x.zip",
            "https://github.com.evil.example/x.zip",
            "https://blob.core.windows.net.evil.example/x",
            // Userinfo smuggles an authority-lookalike; refuse it outright.
            "https://github.com@evil.example/x.zip",
            // Bare nonsense and relative spellings are not redirect targets.
            "not-a-url",
            "/relative/path",
            "",
        ] {
            assert!(signed_redirect_target(bad).is_err(), "must refuse {bad}");
        }
    }

    /// The signed URL rides to curl inside a `-K -` stdin config - never
    /// argv - so a character that would break out of curl's quoting is a
    /// hard refusal before any process spawns.
    #[cfg(unix)]
    #[test]
    fn a_signed_url_that_breaks_config_quoting_never_reaches_curl() {
        for bad in [
            "https://objects.githubusercontent.com/x\"-k evil",
            "https://objects.githubusercontent.com/x.zip?sig=a\\\nurl = \"http://evil\"",
            "https://objects.githubusercontent.com/x.zip?sig=a\rb",
        ] {
            let mut sink = Vec::new();
            assert!(
                stream_signed_target(bad, &mut sink).is_err(),
                "must refuse {bad}"
            );
        }
        // A refusal names the host, never the signed URL's query - the
        // signature inside it is a download credential.
        let err = signed_redirect_target("https://evil.example/x?sig=SECRET")
            .unwrap_err()
            .to_string();
        assert!(err.contains("evil.example"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }

    /// The response head is complete at the CRLF blank line - that bound
    /// lets the reader stop while curl is still streaming the body, so a
    /// transfer bigger than the pipe capacity cannot deadlock the hop.
    /// Trailing bytes after the cut (a body curl wrote through `-D` only
    /// up to the head) never reach the parser.
    #[test]
    fn a_response_head_is_complete_at_the_blank_line() {
        // Every complete head ends AT the CRLF blank line.
        let raw = b"HTTP/2 200\r\ncontent-type: application/zip\r\nlocation: https://x.blob.core.windows.net/a\r\n\r\n";
        let (status, redirect) = parse_response_head(raw).expect("a complete head");
        assert_eq!(status, 200);
        assert_eq!(redirect, "https://x.blob.core.windows.net/a");

        // A 302 the way GitHub answers /logs.
        let raw = b"HTTP/2 302\r\nlocation: https://objects.githubusercontent.com/y?sig=z\r\n\r\n";
        let (status, redirect) = parse_response_head(raw).expect("a complete head");
        assert_eq!(status, 302);
        assert_eq!(redirect, "https://objects.githubusercontent.com/y?sig=z");

        // Location matching is case-insensitive per HTTP.
        let raw = b"HTTP/1.1 301\r\nLocation: https://github.com/a\r\n\r\n";
        assert_eq!(parse_response_head(raw).unwrap().1, "https://github.com/a");
    }

    /// Bytes that arrive after the blank line are the body, not the head:
    /// the parser cuts at the terminator and never reads them - that is
    /// what lets a still-streaming body not deadlock the hop.
    #[test]
    fn a_response_head_ignores_body_bytes_after_the_cut() {
        let raw = b"HTTP/2 200\r\ncontent-length: 999\r\n\r\nBODY-BYTES-CONTINUE\r\nlocation: https://decoy.example/\r\n";
        let (status, redirect) = parse_response_head(raw).expect("a complete head");
        assert_eq!(status, 200);
        assert_eq!(redirect, "");
        // An unterminated head is no head at all - refuse instead of
        // parsing a truncated block.
        assert!(parse_response_head(b"HTTP/2 200\r\ncontent-type: text/plain\r\n").is_none());
    }

    #[test]
    fn transport_output_splits_the_status_and_redirect_trailer() {
        // Body text, then \nSTATUS\nREDIRECT - exactly what -w appends.
        let out = b"log line\nmore log\n302\nhttps://x.blob.core.windows.net/a?sig=z";
        let (body, status, redirect) = split_transport_output(out);
        assert_eq!(body, b"log line\nmore log");
        assert_eq!(status, 302);
        assert_eq!(redirect, "https://x.blob.core.windows.net/a?sig=z");

        // A non-redirect answer carries an empty redirect field.
        let out = b"{\"ok\":true}\n200\n";
        let (body, status, redirect) = split_transport_output(out);
        assert_eq!(body, b"{\"ok\":true}");
        assert_eq!(status, 200);
        assert_eq!(redirect, "");

        // A binary body keeps every byte: the zip magic must not be cut.
        let mut zip = b"PK\x03\x04\nbinary\xffbytes".to_vec();
        zip.extend_from_slice(b"\n200\n");
        let (body, status, _) = split_transport_output(&zip);
        assert_eq!(body, b"PK\x03\x04\nbinary\xffbytes");
        assert_eq!(status, 200);
    }

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
        // The release asset host is the one other origin a token may reach.
        assert_eq!(
            request_url("https://uploads.github.com/repos/o/r/releases/9/assets?name=a.zip")
                .unwrap(),
            "https://uploads.github.com/repos/o/r/releases/9/assets?name=a.zip"
        );
        for hostile in [
            "https://evil.example/user",
            "http://api.github.com/user",
            "http://uploads.github.com/repos/o/r/releases/9/assets",
            "https://api.github.com.evil.example/user",
            "https://uploads.github.com.evil.example/assets",
            "https://api.github.com@evil.example/",
            "https://uploads.github.com@evil.example/",
        ] {
            assert!(request_url(hostile).is_err(), "must refuse {hostile}");
        }
        // The upload origin gets the same traversal judgement as the API origin.
        assert!(request_url("https://uploads.github.com/repos/o/r/../releases/9/assets").is_err());
        assert!(request_url("https://uploads.github.com/repos/o%2fr/releases/9/assets").is_err());
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
            source_digest: None,
        };
        let repo = Repo::for_test("/tmp/x", Some("git@github.com:Attacker/Repo.git"));
        let outcome = crate::identity::resolve(&cfg, &repo, false).unwrap();
        assert!(
            outcome.via_default,
            "an unrouted repository must not look routed"
        );
    }

    /// The streamed-body handoff must reach EOF: the child inherits only the
    /// pipe's read end, because an inherited writer inside the child would
    /// hold the pipe open forever and the request would hang instead of
    /// completing. `cat /dev/fd/N` stands in for curl's `--data-binary` read.
    #[cfg(unix)]
    #[test]
    fn a_streamed_request_reaches_eof_when_the_producer_closes() {
        use std::io::Write as _;
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::process::CommandExt as _;
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        for fd in fds {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                -1,
                "cannot mark the pipe close-on-exec"
            );
        }
        let (reader, mut writer) = unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        };
        let inherited = reader.as_raw_fd();
        let mut command = Command::new("cat");
        command
            .arg(format!("/dev/fd/{inherited}"))
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(inherited, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("cat must spawn");
        drop(reader);
        writer.write_all(b"streamed payload").unwrap();
        drop(writer);
        // A bounded wait: the defect this guards against is a child that
        // never sees EOF, so the proof of completion cannot wait forever.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the child never reached EOF - it still holds a pipe writer");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.stdout, b"streamed payload");
    }
}
