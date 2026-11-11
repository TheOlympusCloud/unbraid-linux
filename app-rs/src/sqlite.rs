//! SQLite databases opened at a version and upgraded in place, as Android's open helper does.
//! The part of Android's SQLite API the statistics use, so that code and its schema stay as they are.

use crate::error::{Error, Result};
use rusqlite::types::Value;
use std::path::{Path, PathBuf};

pub struct SqliteDatabase {
    c: rusqlite::Connection,
}

impl SqliteDatabase {
    /// The database in `file`, made if it is missing.
    pub fn open(file: &Path) -> Result<Self> {
        Ok(SqliteDatabase { c: rusqlite::Connection::open(file).map_err(db)? })
    }

    pub fn exec_sql(&self, sql: &str, args: impl rusqlite::Params) -> Result<()> {
        self.c.execute(sql, args).map(drop).map_err(db)
    }

    pub fn raw_query(&self, sql: &str, args: &[&str]) -> Result<Cursor> {
        let mut st = self.c.prepare(sql).map_err(db)?;
        let n = st.column_count();
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| (0..n).map(|i| r.get::<_, Value>(i)).collect::<rusqlite::Result<Vec<_>>>())
            .and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>)
            .map_err(db)?;
        Ok(Cursor { rows: rows.into_iter(), row: Vec::new() })
    }

    /// Runs `f` in one transaction: committed if it returns, rolled back if it fails.
    pub fn transaction<T>(&self, f: impl FnOnce(&SqliteDatabase) -> Result<T>) -> Result<T> {
        let tx = self.c.unchecked_transaction().map_err(db)?;
        let out = f(self)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }

    pub fn version(&self) -> Result<i32> {
        self.c.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db)
    }

    pub fn set_version(&self, v: i32) -> Result<()> {
        self.c.execute_batch(&format!("PRAGMA user_version = {v}")).map_err(db)
    }
}

/// A query's rows, read the Android way: [`Cursor::move_to_next`], then columns by index from 0, converted as SQLite
/// converts them (NULL reads as 0).
pub struct Cursor {
    rows: std::vec::IntoIter<Vec<Value>>,
    row: Vec<Value>,
}

impl Cursor {
    pub fn move_to_next(&mut self) -> bool {
        self.rows.next().map(|r| self.row = r).is_some()
    }

    pub fn get_string(&self, i: usize) -> Result<String> {
        match self.column(i)? {
            Value::Null => Err(Error::State(format!("column {i} is null"))),
            Value::Integer(n) => Ok(n.to_string()),
            Value::Real(f) => Ok(format!("{f:?}")),
            Value::Text(t) => Ok(t.clone()),
            Value::Blob(b) => Ok(String::from_utf8_lossy(b).into_owned()),
        }
    }

    pub fn get_int(&self, i: usize) -> Result<i32> {
        self.get_long(i).map(|n| n as i32)
    }

    pub fn get_long(&self, i: usize) -> Result<i64> {
        Ok(match self.column(i)? {
            Value::Integer(n) => *n,
            Value::Real(f) => *f as i64,
            Value::Text(t) => t.trim().parse().unwrap_or(0),
            Value::Null | Value::Blob(_) => 0,
        })
    }

    fn column(&self, i: usize) -> Result<&Value> {
        self.row.get(i).ok_or_else(|| Error::State(format!("no column {i} in this row")))
    }
}

/// What makes and upgrades a database's tables, as Android's onCreate and onUpgrade.
pub trait Schema {
    fn on_create(&mut self, d: &SqliteDatabase) -> Result<()>;
    fn on_upgrade(&mut self, d: &SqliteDatabase, old: i32, new: i32) -> Result<()>;
}

/// Android's open helper: creates the file at `version`, or upgrades an older one, in one transaction.
pub struct SqliteOpenHelper<S: Schema> {
    file: PathBuf,
    version: i32,
    pub schema: S,
    db: Option<SqliteDatabase>,
}

impl<S: Schema> SqliteOpenHelper<S> {
    pub fn new(file: PathBuf, version: i32, schema: S) -> Self {
        SqliteOpenHelper { file, version, schema, db: None }
    }

    pub fn writable_database(&mut self) -> Result<&SqliteDatabase> {
        let d = match self.db.take() {
            Some(d) => d,
            None => {
                let d = SqliteDatabase::open(&self.file)?;
                let (old, want, schema) = (d.version()?, self.version, &mut self.schema);
                if old != want {
                    d.transaction(|d| {
                        if old == 0 { schema.on_create(d)? } else { schema.on_upgrade(d, old, want)? }
                        d.set_version(want)
                    })?;
                }
                d
            }
        };
        Ok(self.db.insert(d))
    }

    pub fn close(&mut self) {
        self.db = None;
    }
}

/// A database error, as the earlier app's SQLException: the file couldn't be read or written.
fn db(e: rusqlite::Error) -> Error {
    Error::Io(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Android's open helper: created at its version, upgraded from an older one, in place.
    #[test]
    fn sqlite_helper_creates_and_upgrades() {
        #[derive(Default)]
        struct H {
            steps: Vec<String>,
        }
        impl Schema for H {
            fn on_create(&mut self, d: &SqliteDatabase) -> Result<()> {
                self.steps.push("create".into());
                d.exec_sql("CREATE TABLE t(a INTEGER, b TEXT)", [])
            }
            fn on_upgrade(&mut self, d: &SqliteDatabase, old: i32, new: i32) -> Result<()> {
                self.steps.push(format!("upgrade {old}>{new}"));
                d.exec_sql("ALTER TABLE t ADD COLUMN c INTEGER NOT NULL DEFAULT 7", [])
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("s.db");
        let mut h = SqliteOpenHelper::new(f.clone(), 1, H::default());
        h.writable_database().unwrap().exec_sql("INSERT INTO t VALUES(?,?)", rusqlite::params![1, "x"]).unwrap();
        assert_eq!(vec!["create"], h.schema.steps);
        h.close();

        let mut h = SqliteOpenHelper::new(f, 2, H::default());
        let mut c = h.writable_database().unwrap().raw_query("SELECT a, b, c FROM t WHERE b = ?", &["x"]).unwrap();
        let mut rows = Vec::new();
        while c.move_to_next() {
            rows.push((c.get_long(0).unwrap(), c.get_string(1).unwrap(), c.get_int(2).unwrap()));
        }
        assert_eq!(vec![(1i64, "x".to_string(), 7)], rows);
        assert_eq!(vec!["upgrade 1>2"], h.schema.steps);
        let d = h.writable_database().unwrap();
        assert!(d.transaction(|d| { d.exec_sql("INSERT INTO t VALUES(2,'y',0)", [])?; Err::<(), _>(Error::State("rolled back".into())) }).is_err());
        let mut c = d.raw_query("SELECT COUNT(*) FROM t", &[]).unwrap();
        assert!(c.move_to_next());
        assert_eq!(1, c.get_int(0).unwrap());
        h.close();
    }
}
