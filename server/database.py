"""
Database setup — MySQL (production) or SQLite (local dev).
Set DB_ENGINE=mysql and DB_HOST/DB_NAME/DB_SECRET to use MySQL.
"""
import os
import json
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DB_ENGINE = os.getenv("DB_ENGINE", "sqlite")


# ── MySQL ─────────────────────────────────────────────────────────────────────

def _mysql_creds():
    secret = os.getenv("DB_SECRET", "")
    if secret:
        try:
            d = json.loads(secret)
            return d.get("username", ""), d.get("password", "")
        except Exception:
            pass
    return os.getenv("DB_USER", ""), os.getenv("DB_PASSWORD", "")


def _get_mysql():
    import pymysql
    user, password = _mysql_creds()
    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=user,
        password=password,
        database=os.getenv("DB_NAME", "sandwalk"),
        autocommit=False,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    return conn


class _MySQLRow(dict):
    """Makes MySQL DictCursor rows behave like sqlite3.Row (field access by name)."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

    def keys(self):
        return super().keys()


def _wrap_mysql_conn(conn):
    """Wrap a pymysql connection so execute() returns rows compatible with sqlite3.Row."""
    original_execute = conn.cursor().__class__.execute

    class WrappedCursor:
        def __init__(self, cursor):
            self._c = cursor

        def execute(self, sql, params=None):
            # Translate SQLite ? placeholders to MySQL %s
            sql = sql.replace("?", "%s")
            if params is not None:
                self._c.execute(sql, params)
            else:
                self._c.execute(sql)
            return self

        def executemany(self, sql, seq):
            sql = sql.replace("?", "%s")
            self._c.executemany(sql, seq)

        def fetchone(self):
            row = self._c.fetchone()
            return _MySQLRow(row) if row else None

        def fetchall(self):
            return [_MySQLRow(r) for r in self._c.fetchall()]

        @property
        def rowcount(self):
            return self._c.rowcount

        @property
        def lastrowid(self):
            return self._c.lastrowid

    class WrappedConn:
        def __init__(self, c):
            self._c = c

        def execute(self, sql, params=None):
            cur = WrappedCursor(self._c.cursor())
            cur.execute(sql, params)
            return cur

        def executescript(self, sql):
            # Split on semicolons and run each statement
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    try:
                        self._c.cursor().execute(stmt)
                    except Exception:
                        pass

        def commit(self):
            self._c.commit()

        def rollback(self):
            self._c.rollback()

        def close(self):
            self._c.close()

    return WrappedConn(conn)


# ── SQLite ────────────────────────────────────────────────────────────────────

_default_db = Path.home() / ".sandwalk" / "db.sqlite"
_default_db.parent.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("DB_PATH", str(_default_db)))


def _get_sqlite():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── Public interface ──────────────────────────────────────────────────────────

def get_connection():
    if DB_ENGINE == "mysql":
        return _wrap_mysql_conn(_get_mysql())
    return _get_sqlite()


@contextmanager
def db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if not exist. MySQL tables are created by the consumer Lambda."""
    if DB_ENGINE == "mysql":
        # Column migrations against the existing MySQL schema. MySQL implicitly
        # commits DDL, so each ALTER takes effect on its own.
        with db() as conn:
            for ddl in (
                "ALTER TABLE findings ADD COLUMN file_paths TEXT",
                "ALTER TABLE machines ADD COLUMN fda_granted TINYINT(1)",
            ):
                try:
                    conn.execute(ddl)
                except Exception:
                    pass  # column already exists
        return

    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS machines (
                id          TEXT PRIMARY KEY,
                hostname    TEXT NOT NULL,
                username    TEXT NOT NULL,
                os          TEXT NOT NULL,
                os_version  TEXT,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                agent_version TEXT,
                fda_granted INTEGER
            );

            CREATE TABLE IF NOT EXISTS scans (
                id              TEXT PRIMARY KEY,
                machine_id      TEXT NOT NULL REFERENCES machines(id),
                scanned_at      TEXT NOT NULL,
                scope           TEXT NOT NULL DEFAULT 'standard',
                finding_count   INTEGER NOT NULL DEFAULT 0,
                duration_ms     INTEGER
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                scan_id         TEXT NOT NULL,
                machine_id      TEXT NOT NULL,
                pattern_id      TEXT NOT NULL,
                pattern_name    TEXT NOT NULL,
                severity        TEXT NOT NULL,
                category        TEXT NOT NULL,
                source_type     TEXT NOT NULL DEFAULT 'machine',
                file_path       TEXT NOT NULL,
                line_number     INTEGER,
                value_hash      TEXT NOT NULL,
                value_preview   TEXT NOT NULL,
                context_line    TEXT,
                verified_active INTEGER,
                ssh_has_passphrase INTEGER,
                commit_hash     TEXT,
                commit_author   TEXT,
                commit_date     TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'open',
                remediated_at   TEXT,
                notes           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_findings_machine ON findings(machine_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_value_hash ON findings(value_hash);
            CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source_type);

            CREATE TABLE IF NOT EXISTS rescan_requests (
                id              TEXT PRIMARY KEY,
                machine_id      TEXT NOT NULL,
                requested_at    TEXT NOT NULL,
                scope           TEXT NOT NULL DEFAULT 'standard',
                status          TEXT NOT NULL DEFAULT 'pending',
                fulfilled_at    TEXT
            );
        """)
        # Migrations — safe to run on existing DBs
        for ddl in (
            "ALTER TABLE findings ADD COLUMN file_paths TEXT",
            "ALTER TABLE machines ADD COLUMN fda_granted INTEGER",
        ):
            try:
                conn.execute(ddl)
            except Exception:
                pass  # column already exists
