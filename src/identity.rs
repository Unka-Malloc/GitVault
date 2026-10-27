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
//! disagrees with the remote owner rule, the rule wins and the mismatch is
//! reported rather than honoured. A repository can declare what it expects; it
//! cannot grant itself an identity the owner rules do not allow - which is why
//! credential-issuing paths resolve with `ignore_assertion = true`, so untrusted
//! repository content can never pick which account's credentials are used.

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
    if !repo.assertion_allowed {
        return Ok(None);
    }
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
        bail!("{} names unknown identity '{value}'", path.display());
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
        match (&owner_rule, owner.as_deref()) {
            // The assertion is a contract, not a selector: a rule that disagrees
            // wins the identity, and the mismatch is reported rather than
            // honoured. Otherwise an untrusted file could grant this repository
            // an identity the rules did not allow.
            (Some(rule), Some(o)) if rule != &a => (
                rule.clone(),
                format!("rules.owners['{o}']"),
                Some(format!(
                    "{ASSERTION_FILE} asserts '{a}' but rules.owners maps '{o}' to '{rule}'"
                )),
                false,
            ),
            _ => (a, format!("{ASSERTION_FILE} assertion"), None, false),
        }
    } else if let Some(rule) = owner_rule.clone() {
        (
            rule,
            format!("rules.owners['{}']", owner.clone().unwrap_or_default()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Identity, PathRule, Rules};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn identity(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            email: format!("{name}@example.test"),
            account: Some(name.to_string()),
            ssh_key: None,
            signing_key: None,
        }
    }

    fn cfg(owners: &[(&str, &str)], default: Option<&str>) -> Config {
        Config {
            identities: ["personal", "acme"]
                .into_iter()
                .map(|k| (k.to_string(), identity(k)))
                .collect::<BTreeMap<_, _>>(),
            rules: Rules {
                owners: owners
                    .iter()
                    .map(|(o, i)| (o.to_string(), i.to_string()))
                    .collect(),
                paths: Vec::<PathRule>::new(),
                default: default.map(str::to_string),
                release_asset_budget: None,
            },
            audit_policy: None,
            record_dir: None,
            path: None,
            source_digest: None,
        }
    }

    /// A working tree carrying a `.gitvault-identity` file.
    struct AssertingTree {
        root: PathBuf,
    }

    impl AssertingTree {
        fn new(tag: &str, assertion: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("gv-identity-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join(ASSERTION_FILE), format!("{assertion}\n")).unwrap();
            Self { root }
        }

        fn repo(&self, remote: &str) -> Repo {
            Repo::for_test(self.root.to_str().unwrap(), Some(remote))
        }
    }

    impl Drop for AssertingTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn conflicting_assertion_loses_to_owner_rule() {
        let tree = AssertingTree::new("conflict", "acme");
        let repo = tree.repo("git@github.com:acme-org/repo.git");
        let cfg = cfg(&[("acme-org", "personal")], None);
        let outcome = resolve(&cfg, &repo, false).unwrap();
        // The rule wins; the mismatch is reported, not honoured.
        assert_eq!(outcome.identity, "personal");
        assert!(outcome.conflict.is_some());
        assert!(!outcome.via_default);
        assert_eq!(outcome.assertion.as_deref(), Some("acme"));
    }

    #[test]
    fn consistent_assertion_is_honoured() {
        let tree = AssertingTree::new("agree", "personal");
        let repo = tree.repo("git@github.com:acme-org/repo.git");
        let cfg = cfg(&[("acme-org", "personal")], None);
        let outcome = resolve(&cfg, &repo, false).unwrap();
        assert_eq!(outcome.identity, "personal");
        assert!(outcome.conflict.is_none());
    }

    #[test]
    fn assertion_cannot_route_credentials() {
        let tree = AssertingTree::new("unrouted", "personal");
        let repo = tree.repo("git@github.com:nobody/repo.git");
        let cfg = cfg(&[], None);
        // The check path may read the assertion as the declared expectation...
        let outcome = resolve(&cfg, &repo, false).unwrap();
        assert_eq!(outcome.identity, "personal");
        // ...but a credential path resolves without it, and then there is no
        // rule at all - which must fail rather than hand out an identity.
        assert!(resolve(&cfg, &repo, true).is_err());
    }

    #[test]
    fn slug_handles_carry_no_assertion() {
        // `gitvault api --repo other/name` must never read this checkout's
        // assertion file against a different repository.
        let repo = Repo::for_slug("other/name");
        assert!(!repo.assertion_allowed);
        let cfg = cfg(&[("other", "acme")], None);
        let outcome = resolve(&cfg, &repo, false).unwrap();
        assert!(outcome.assertion.is_none());
        assert_eq!(outcome.identity, "acme");
    }

    #[test]
    fn unrouted_repository_falls_back_as_default() {
        let tree = AssertingTree::new("default", "unknown-identity");
        let repo = tree.repo("git@github.com:nobody/repo.git");
        let cfg = cfg(&[], Some("personal"));
        // The assertion names an unknown identity: a hard error even though a
        // default exists, because failing open would defeat the file's purpose.
        assert!(resolve(&cfg, &repo, false).is_err());
        let outcome = resolve(&cfg, &repo, true).unwrap();
        assert!(outcome.via_default);
        assert_eq!(outcome.identity, "personal");
    }
}
