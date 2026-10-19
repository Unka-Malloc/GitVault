//! Session concealment by recorded ID. Every audit run keeps an
//! `audit-session.json` — `session_id` for resume, `session_ids` for every
//! conversation the run ever opened (stale-resume retries and fallback lanes
//! included). Once the run is done, those sessions have served their turn:
//! the sweep marks them archived in each admitted agent's store so they leave
//! the operator's session list while staying resumable. Neither admitted
//! agent exposes an archive verb over its lane (`devin rm` deletes,
//! opencode's serve update ignores `time.archived`), so the sweep flips each
//! store's native list flag directly: `hidden` on devin's sessions.db,
//! `time_archived` on opencode's session_v2, and
//! `info._meta."cognition.ai/isArchived"` on the Devin desktop's
//! globalStorage session index — the sidebar renders that index, not the CLI
//! database. Concealment is best-effort housekeeping: a missing store or a
//! refused write warns on stderr and never fails the gate.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The desktop session-index record name for a devin-cli conversation.
const VSCDB_KEY: &str = "windsurf.acp.sessioninfo.session.acp/devin-cli/";

/// One harness session store: the database path under `$HOME`, the table
/// holding sessions, and the SQL boolean selecting recorded sessions.
struct Store {
    db: &'static str,
    table: &'static str,
    /// Row predicate over the recorded ids, e.g. `id IN ('a','b')`.
    match_: fn(ids: &BTreeSet<String>) -> String,
    /// The archive flag assignment for a concealed row.
    set: fn(now_ms: i64) -> String,
    /// The predicate keeping already-concealed rows untouched.
    pending: &'static str,
}

fn ids_in(ids: &BTreeSet<String>) -> String {
    format!("id IN ({})", quote_all(ids.iter()))
}

fn keys_in(ids: &BTreeSet<String>) -> String {
    let keys = ids.iter().map(|id| format!("{VSCDB_KEY}{id}"));
    format!("key IN ({})", quote_all(keys))
}

fn quote_all<'a>(values: impl Iterator<Item = impl AsRef<str> + 'a>) -> String {
    values
        .map(|value| format!("'{}'", value.as_ref().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",")
}

const STORES: &[Store] = &[
    Store {
        db: ".local/share/opencode/opencode.db",
        table: "session_v2",
        match_: ids_in,
        set: |now_ms| format!("time_archived = {now_ms}"),
        pending: "time_archived IS NULL",
    },
    Store {
        db: ".local/share/devin/cli/sessions.db",
        table: "sessions",
        match_: ids_in,
        set: |_| "hidden = 1".to_string(),
        pending: "hidden IS NOT 1",
    },
    Store {
        db: "Library/Application Support/Devin/User/globalStorage/state.vscdb",
        table: "ItemTable",
        match_: keys_in,
        set: |_| {
            "value = json_set(value, '$.info._meta.\"cognition.ai/isArchived\"', json('true'))"
                .to_string()
        },
        pending: "json_extract(value, '$.info._meta.\"cognition.ai/isArchived\"') IS NOT 1",
    },
];

/// Archive every session recorded under `runs_dir` in each admitted agent's
/// store: one UPDATE per store over the collected id list.
pub fn run_sessions(runs_dir: &Path) {
    let ids = recorded_ids(runs_dir);
    if ids.is_empty() {
        return;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let now_ms = jiff::Zoned::now().timestamp().as_millisecond();
    for store in STORES {
        let db = Path::new(&home).join(store.db);
        if !db.is_file() {
            continue;
        }
        // The desktop and the harnesses hold their stores open; wait out a
        // transient writer instead of refusing on `database is locked`.
        let sql = format!(
            "PRAGMA busy_timeout = 15000; UPDATE {} SET {} WHERE {} AND {};",
            store.table,
            (store.set)(now_ms),
            (store.match_)(&ids),
            store.pending
        );
        match Command::new("sqlite3").arg(&db).arg(&sql).output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => eprintln!(
                "conceal: {} refused: {}",
                db.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(error) => eprintln!("conceal: {} refused: {error}", db.display()),
        }
    }
}

/// Every session id recorded under `runs_dir`: each run's
/// `audit-session.json` contributes `session_ids` (all conversations the run
/// opened) plus the scalar `session_id` for files written before the list
/// field existed.
fn recorded_ids(runs_dir: &Path) -> BTreeSet<String> {
    let Ok(entries) = std::fs::read_dir(runs_dir) else {
        return BTreeSet::new();
    };
    let mut ids = BTreeSet::new();
    for entry in entries.flatten() {
        let file = entry.path().join("audit-session.json");
        let Ok(raw) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Ok(saved) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        if let Some(id) = saved["session_id"].as_str() {
            ids.insert(id.to_string());
        }
        if let Some(list) = saved["session_ids"].as_array() {
            ids.extend(list.iter().filter_map(|id| id.as_str().map(str::to_string)));
        }
    }
    ids
}
