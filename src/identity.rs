//! Identity resolution: decide which identity may act on a repository, and say why.
//!
//! Order of precedence, first match wins:
//!   1. `--identity` on the command line
//!   2. `.gitvault-identity` in the repository root  (an assertion, see below)
//!   3. `rules.owners`     matched against the origin remote's owner
//!   4. `rules.paths`      matched against the working tree path
//!   5. `rules.default`
//!
//! **The assertion is a contract, not a selector.** If `.gitvault-identity`
//! names an identity, that identity is used - and the *remote owner rule is then
//! still evaluated*, so a mismatch is reported rather than silently accepted.
//! A repository can declare what it expects; it cannot grant itself an identity
//! that the owner rules do not allow.

use anyhow::{Result, bail};
use serde_json::json;

use crate::config::Config;
use crate::git::Repo;

pub const ASSERTION_FILE: &str = ".gitvault-identity";

#[derive(Debug, Clone)]
pub struct Outcome {
    pub identity: String,
    pub account: Option<String>,
    /// Identity declared by the validation rules (what SHOULD be used).
    pub expected_email: Option<String>,
    /// What git will actually stamp on the commit. Attribution follows this one.
    pub actual_email: Option<String>,
    pub reason: String,
    /// The identity came from `rules.default`, not a rule about this
    /// repository. Credential-issuing paths refuse a default route: a fallback
    /// must never be a credential source. Carried as a field, not parsed out
    /// of `reason`, so a wording change cannot silently open the gate.
    pub via_default: bool,
    /// Set when the assertion disagreed with the owner rule.
    pub conflict: Option<String>,
    pub assertion: Option<String>,
}

impl Outcome {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "identity": self.identity,
            "account": self.account,
            "expected_email": self.expected_email,
            "actual_email": self.actual_email,
            "reason": self.reason,
            "via_default": self.via_default,
            "assertion": self.assertion,
            "conflict": self.conflict,
        })
    }
}

/// Read the repository's assertion file. A malformed or unknown assertion is a
/// hard error: failing open here would defeat the purpose of having it.
fn read_assertion(repo: &Repo, cfg: &Config) -> Result<Option<String>> {
    let path = repo.root.join(ASSERTION_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    // First non-empty, non-comment line.
    let value = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string);
    let Some(value) = value else {
        return Ok(None);
    };
    if !cfg.identities.contains_key(&value) {
        bail!(
            "{} names unknown identity '{value}'",
            path.display()
        );
    }
    Ok(Some(value))
}

fn lookup<'a>(cfg: &'a Config, key: &str) -> Result<&'a crate::config::Identity> {
    cfg.identities
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("identity '{key}' is not defined"))
}

pub fn resolve(cfg: &Config, repo: &Repo, ignore_assertion: bool) -> Result<Outcome> {
    let assertion = if ignore_assertion {
        None
    } else {
        read_assertion(repo, cfg)?
    };

    let owner = repo.owner();
    let owner_rule = owner
        .as_ref()
        .and_then(|o| cfg.rules.owners.get(o))
        .cloned();

    let (chosen, reason, conflict, via_default) = if let Some(a) = assertion.clone() {
        let conflict = match (&owner_rule, owner.as_deref()) {
            (Some(rule), Some(o)) if rule != &a => Some(format!(
                "{ASSERTION_FILE} asserts '{a}' but rules.owners maps '{o}' to '{rule}'"
            )),
            _ => None,
        };
        (a, format!("{ASSERTION_FILE} assertion"), conflict, false)
    } else if let Some(rule) = owner_rule.clone() {
        (
            rule,
            format!(
                "rules.owners['{}']",
                owner.clone().unwrap_or_default()
            ),
            None,
            false,
        )
    } else if let Some(rule) = cfg
        .rules
        .paths
        .iter()
        .find(|r| repo.root.starts_with(&r.prefix))
    {
        (
            rule.identity.clone(),
            format!("rules.paths['{}']", rule.prefix.display()),
            None,
            false,
        )
    } else if let Some(default) = cfg.rules.default.clone() {
        (default, "rules.default".to_string(), None, true)
    } else {
        bail!(
            "no identity matches repository {} (remote owner: {})\n\
             add a rules.owners entry, or set rules.default explicitly",
            repo.root.display(),
            owner.as_deref().unwrap_or("(none)")
        );
    };

    let id = lookup(cfg, &chosen)?;
    Ok(Outcome {
        identity: chosen,
        account: id.account.clone(),
        expected_email: Some(id.email.clone()),
        // Read git's effective user.email. When this differs from expected_email the
        // commit will be attributed to the wrong account no matter what the rules say.
        actual_email: repo.configured_email(),
        reason,
        via_default,
        conflict,
        assertion,
    })
}
