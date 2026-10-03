//! Where the desk's state lives between restarts: a JSON file (rewritten whole
//! on every save) or a SQLite database (one row per record, and a save only
//! touches the rows that changed, in one transaction).
//!
//! Both take and return the same JSON document, so the engine does not care
//! which one it has. In SQLite every top-level field of that document becomes
//! a `kind`; arrays are stored one element per row (keyed by the element's
//! `id`, else its position) and objects one entry per row.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, params};
use serde_json::{Map, Value};

use crate::error::Error;

pub enum Store {
    Json(PathBuf),
    Sqlite(SqliteStore),
}

pub struct SqliteStore {
    path: PathBuf,
    conn: Mutex<Connection>,
    /// What each row held at the last save, to write only what changed.
    saved: Mutex<HashMap<(String, String), String>>,
}

/// Row key prefixes, so a kind's shape (array or object) survives the trip.
const ARRAY_ROW: char = 'a';
const OBJECT_ROW: char = 'o';

impl Store {
    /// SQLite for `.db` / `.sqlite` / `.sqlite3` paths, JSON otherwise.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let sqlite = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("db" | "sqlite" | "sqlite3")
        );
        if !sqlite {
            return Ok(Self::Json(path));
        }
        let fail = |e: rusqlite::Error| Error::Invalid(format!("open {}: {e}", path.display()));
        // Preimages and funding keys live here: owner-only. SQLite gives its
        // -wal / -shm files the database's mode.
        create_private(&path).map_err(|e| Error::Invalid(format!("open {}: {e}", path.display())))?;
        let conn = Connection::open(&path).map_err(fail)?;
        // WAL survives a crash mid-write; FULL syncs every commit, since the
        // state holds HTLC preimages the desk cannot afford to lose.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS records (
                 kind TEXT NOT NULL,
                 id   TEXT NOT NULL,
                 body TEXT NOT NULL,
                 PRIMARY KEY (kind, id)
             );",
        )
        .map_err(fail)?;
        Ok(Self::Sqlite(SqliteStore {
            path,
            conn: Mutex::new(conn),
            saved: Mutex::default(),
        }))
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Json(p) => p,
            Self::Sqlite(s) => &s.path,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Json(_) => "json",
            Self::Sqlite(_) => "sqlite",
        }
    }

    /// The saved document, or `None` if nothing was ever saved.
    pub fn load(&self) -> Result<Option<Value>, Error> {
        match self {
            Self::Json(path) => {
                let raw = match std::fs::read_to_string(path) {
                    Ok(raw) => raw,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(err) => return Err(Error::Invalid(format!("read {}: {err}", path.display()))),
                };
                serde_json::from_str(&raw)
                    .map(Some)
                    .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))
            }
            Self::Sqlite(s) => s.load(),
        }
    }

    /// Persist `doc` (blocking; call from `spawn_blocking`).
    pub fn save(&self, doc: &Value) -> Result<(), Error> {
        match self {
            Self::Json(path) => {
                let json = serde_json::to_vec_pretty(doc).map_err(|e| Error::Invalid(e.to_string()))?;
                write_atomic(path, &json).map_err(|e| Error::Invalid(format!("write {}: {e}", path.display())))
            }
            Self::Sqlite(s) => s.save(doc),
        }
    }

    /// Rows written so far (SQLite only; for tests and stats).
    pub fn row_count(&self) -> Option<usize> {
        match self {
            Self::Json(_) => None,
            Self::Sqlite(s) => s.saved.lock().ok().map(|m| m.len()),
        }
    }
}

impl SqliteStore {
    fn load(&self) -> Result<Option<Value>, Error> {
        let corrupt = |why: String| Error::Invalid(format!("{}: {why}", self.path.display()));
        let conn = self.conn.lock().map_err(|_| corrupt("lock poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT kind, id, body FROM records ORDER BY kind, id")
            .map_err(|e| corrupt(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(|e| corrupt(e.to_string()))?;
        let mut doc = Map::new();
        let mut saved = HashMap::new();
        for row in rows {
            let (kind, id, body) = row.map_err(|e| corrupt(e.to_string()))?;
            let value: Value =
                serde_json::from_str(&body).map_err(|e| corrupt(format!("{kind}/{id}: {e}")))?;
            let (shape, key) = id.split_at(1);
            let slot = doc.entry(kind.clone()).or_insert_with(|| {
                if shape.starts_with(OBJECT_ROW) {
                    Value::Object(Map::new())
                } else {
                    Value::Array(Vec::new())
                }
            });
            match slot {
                Value::Object(m) => {
                    m.insert(key.to_string(), value);
                }
                Value::Array(v) => v.push(value),
                _ => unreachable!("slots are arrays or objects"),
            }
            saved.insert((kind, id), body);
        }
        if saved.is_empty() {
            return Ok(None);
        }
        *self.saved.lock().map_err(|_| corrupt("lock poisoned".into()))? = saved;
        Ok(Some(Value::Object(doc)))
    }

    fn save(&self, doc: &Value) -> Result<(), Error> {
        let fail = |why: String| Error::Invalid(format!("{}: {why}", self.path.display()));
        let rows = rows_of(doc)?;
        let mut saved = self.saved.lock().map_err(|_| fail("lock poisoned".into()))?;
        let mut conn = self.conn.lock().map_err(|_| fail("lock poisoned".into()))?;
        let tx = conn.transaction().map_err(|e| fail(e.to_string()))?;
        {
            let mut upsert = tx
                .prepare_cached(
                    "INSERT INTO records (kind, id, body) VALUES (?1, ?2, ?3)
                     ON CONFLICT (kind, id) DO UPDATE SET body = excluded.body",
                )
                .map_err(|e| fail(e.to_string()))?;
            for (key, body) in &rows {
                if saved.get(key) != Some(body) {
                    upsert
                        .execute(params![key.0, key.1, body])
                        .map_err(|e| fail(e.to_string()))?;
                }
            }
            let mut delete = tx
                .prepare_cached("DELETE FROM records WHERE kind = ?1 AND id = ?2")
                .map_err(|e| fail(e.to_string()))?;
            for key in saved.keys().filter(|k| !rows.contains_key(*k)) {
                delete.execute(params![key.0, key.1]).map_err(|e| fail(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| fail(e.to_string()))?;
        *saved = rows;
        Ok(())
    }
}

/// Split the document into (kind, row id) → JSON body.
fn rows_of(doc: &Value) -> Result<HashMap<(String, String), String>, Error> {
    let Value::Object(fields) = doc else {
        return Err(Error::Invalid("state must be a JSON object".into()));
    };
    let mut rows = HashMap::new();
    let enc = |v: &Value| serde_json::to_string(v).map_err(|e| Error::Invalid(e.to_string()));
    for (kind, value) in fields {
        match value {
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let key = match item.get("id").and_then(Value::as_str) {
                        Some(id) => format!("{ARRAY_ROW}{id}"),
                        // Positional rows: zero-padded so ORDER BY keeps order.
                        None => format!("{ARRAY_ROW}#{i:010}"),
                    };
                    rows.insert((kind.clone(), key), enc(item)?);
                }
            }
            Value::Object(entries) => {
                for (k, v) in entries {
                    rows.insert((kind.clone(), format!("{OBJECT_ROW}{k}")), enc(v)?);
                }
            }
            other => {
                return Err(Error::Invalid(format!("state field {kind} is not a collection: {other}")));
            }
        }
    }
    Ok(rows)
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = private_options().truncate(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Create `path` owner-only if missing, and tighten it if it already exists.
fn create_private(path: &Path) -> std::io::Result<()> {
    private_options().open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn private_options() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tachi-store-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn sqlite_round_trips_and_writes_only_changes() {
        let path = tmp("state.db");
        let doc = json!({
            "swaps": [{"id": "s1", "amount": 1}, {"id": "s2", "amount": 2}],
            "own_vtxos": ["v1", "v2"],
            "bonds": {"lp-alpha": 50000},
            "plans": [],
        });
        let store = Store::open(&path).unwrap();
        assert_eq!(store.kind(), "sqlite");
        assert!(store.load().unwrap().is_none());
        store.save(&doc).unwrap();
        assert_eq!(store.row_count(), Some(5));

        // Change one swap, drop the other, add a bond.
        let next = json!({
            "swaps": [{"id": "s1", "amount": 10}],
            "own_vtxos": ["v1", "v2"],
            "bonds": {"lp-alpha": 50000, "lp-bravo": 1},
            "plans": [],
        });
        store.save(&next).unwrap();
        drop(store);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "state holds secrets");
        }
        let back = Store::open(&path).unwrap().load().unwrap().unwrap();
        assert_eq!(back["swaps"], json!([{"id": "s1", "amount": 10}]));
        assert_eq!(back["own_vtxos"], json!(["v1", "v2"]));
        assert_eq!(back["bonds"], json!({"lp-alpha": 50000, "lp-bravo": 1}));
        // An empty collection has no rows; the engine defaults it.
        assert!(back.get("plans").is_none());
    }

    #[test]
    fn json_backend_keeps_the_old_file_format() {
        let path = tmp("state.json");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.kind(), "json");
        let doc = json!({"swaps": [{"id": "s1"}]});
        store.save(&doc).unwrap();
        assert_eq!(Store::open(&path).unwrap().load().unwrap(), Some(doc));
    }
}
