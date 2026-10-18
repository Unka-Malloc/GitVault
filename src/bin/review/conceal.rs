//! Session concealment: a finished audit conversation stays in the harness's
//! own store — resumable and receipt-adjacent — but leaves the operator's
//! session list alone. Neither admitted agent exposes an archive verb over
//! its lane (`devin rm` deletes, opencode's serve update ignores
//! `time.archived`), so the sweep flips each store's native list flag
//! directly: `hidden` on devin's sessions.db, `time_archived` on opencode's
//! session_v2. Concealment is best-effort housekeeping: a missing store or a
//! refused write warns on stderr and never fails the gate.

use std::path::Path;
use std::process::Command;

/// One harness session store: the database path under `$HOME`, the table
/// holding sessions, and the column recording the session's working
/// directory. Audit sessions always open with the run directory as cwd, so a
/// directory predicate conceals every session a run created — retries,
/// siblings and fallback-lane conversations included, and runs already
/// pruned from disk included as well.
struct Store {
    db: &'static str,
    table: &'static str,
    directory: &'static str,
    /// The archive flag assignment for a concealed row.
    set: fn(now_ms: i64) -> String,
    /// The predicate keeping already-concealed rows untouched.
    pending: &'static str,
}

const STORES: &[Store] = &[
    Store {
        db: ".local/share/opencode/opencode.db",
        table: "session_v2",
        directory: "directory",
        set: |now_ms| format!("time_archived = {now_ms}"),
        pending: "time_archived IS NULL",
    },
    Store {
        db: ".local/share/devin/cli/sessions.db",
        table: "sessions",
        directory: "working_directory",
        set: |_| "hidden = 1".to_string(),
        pending: "hidden IS NOT 1",
    },
];

/// Conceal every session whose working directory lives under `runs_dir` in
/// each admitted agent's store. `sqlite3` is a platform binary; the call is
/// one UPDATE per store.
pub fn run_sessions(runs_dir: &Path) {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let prefix = like_prefix(&runs_dir.to_string_lossy());
    let now_ms = jiff::Zoned::now().timestamp().as_millisecond();
    for store in STORES {
        let db = Path::new(&home).join(store.db);
        if !db.is_file() {
            continue;
        }
        let sql = format!(
            "UPDATE {} SET {} WHERE {} LIKE '{}%' ESCAPE '\\' AND {};",
            store.table,
            (store.set)(now_ms),
            store.directory,
            prefix,
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

/// A `LIKE ... ESCAPE '\'` prefix's literal interior: `'` doubles for the
/// string literal; `\`, `%` and `_` take the escape.
fn like_prefix(dir: &str) -> String {
    dir.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}
