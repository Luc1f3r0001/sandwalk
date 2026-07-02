"""
Sandwalk findings consumer Lambda.
Triggered by SQS (batch 10). Writes findings to MySQL (RDS).
Credentials from AWS Secrets Manager (auto-rotated RDS secret).
"""
import json
import os
import re
import uuid
import logging
import boto3
import pymysql
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# validate-or-remove policy: only confirmed-active secrets are stored. SSH/TLS
# private keys have no network validator, so the owner's own ~/.ssh keys are the
# sole exception (kept; everything else outside ~/.ssh is noise).
_SSH_OWN_RE = re.compile(r'(/Users/[^/]+|/home/[^/]+|/var/root|/root)/\.ssh/')


def _mask(v):
    """Redact a secret to a prefix + last-4 hint so the DB never stores plaintext
    while the provider stays recognizable: 'sk-ant-api03-...MIJS' -> 'sk-ant-…MIJS'.
    Idempotent-safe. Must match the agent's maskValue() and scans.py _mask()."""
    if not v:
        return v
    v = str(v)
    if "…" in v:            # already a masked hint (from a redacting agent) → keep as-is
        return v
    if len(v) <= 4:
        return "…"
    if len(v) < 14:
        return "…" + v[-4:]
    return v[:7] + "…" + v[-4:]


def _policy_keep(f: dict) -> bool:
    if f.get("verified_active") not in (1, True):
        return False
    if f.get("pattern_id") == "ssh_private_key":
        return bool(_SSH_OWN_RE.search(f.get("file_path", "")))
    return True

DB_HOST   = os.environ.get("DB_HOST", "your-db-host.example.com")
DB_PORT   = int(os.environ.get("DB_PORT", "3306"))
DB_NAME   = os.environ.get("DB_NAME", "sandwalk")
SECRET_ARN = os.environ.get("DB_SECRET_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

_db_conn = None


def _get_credentials() -> tuple[str, str]:
    sm = boto3.client("secretsmanager", region_name=AWS_REGION)
    secret = json.loads(sm.get_secret_value(SecretId=SECRET_ARN)["SecretString"])
    return secret["username"], secret["password"]


def _get_conn():
    global _db_conn
    try:
        if _db_conn:
            _db_conn.ping(reconnect=True)
            return _db_conn
    except Exception:
        _db_conn = None

    user, password = _get_credentials()
    # Connect without DB first to ensure it exists
    tmp = pymysql.connect(host=DB_HOST, port=DB_PORT, user=user,
                          password=password, autocommit=True, charset="utf8mb4")
    with tmp.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    tmp.close()
    _db_conn = pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=user,
        password=password, database=DB_NAME,
        autocommit=True, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    return _db_conn


def _ensure_tables(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS machines (
                id           VARCHAR(36) PRIMARY KEY,
                hostname     VARCHAR(255) NOT NULL,
                username     VARCHAR(255) NOT NULL,
                os           VARCHAR(100),
                os_version   VARCHAR(100),
                agent_version VARCHAR(20),
                fda_granted  TINYINT(1),
                first_seen   DATETIME NOT NULL,
                last_seen    DATETIME NOT NULL
            )
        """)
        # Migrations for existing DBs (CREATE IF NOT EXISTS won't add columns).
        for ddl in ("ALTER TABLE machines ADD COLUMN fda_granted TINYINT(1)",):
            try:
                cur.execute(ddl)
            except Exception:
                pass  # column already exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id               VARCHAR(36) PRIMARY KEY,
                machine_id       VARCHAR(36) NOT NULL,
                pattern_id       VARCHAR(100) NOT NULL,
                pattern_name     VARCHAR(200) NOT NULL,
                severity         VARCHAR(20) NOT NULL,
                category         VARCHAR(50) NOT NULL,
                source_type      VARCHAR(20) NOT NULL DEFAULT 'machine',
                file_path        TEXT NOT NULL,
                file_paths       JSON,
                line_number      INT,
                value_hash       VARCHAR(64) NOT NULL,
                value_preview    TEXT NOT NULL,
                context_line     TEXT,
                verified_active  TINYINT(1),
                ssh_has_passphrase TINYINT(1),
                commit_hash      VARCHAR(64),
                commit_author    VARCHAR(255),
                commit_date      DATETIME,
                first_seen       DATETIME NOT NULL,
                last_seen        DATETIME NOT NULL,
                status           VARCHAR(30) NOT NULL DEFAULT 'open',
                remediated_at    DATETIME,
                notes            TEXT,
                INDEX idx_machine (machine_id),
                INDEX idx_status (status),
                INDEX idx_severity (severity),
                INDEX idx_value_hash (value_hash),
                UNIQUE KEY uq_finding (machine_id, value_hash, pattern_id, source_type)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rescan_requests (
                id           VARCHAR(36) PRIMARY KEY,
                machine_id   VARCHAR(36) NOT NULL,
                requested_at DATETIME NOT NULL,
                scope        VARCHAR(50) NOT NULL DEFAULT 'standard',
                status       VARCHAR(30) NOT NULL DEFAULT 'pending',
                fulfilled_at DATETIME
            )
        """)


def _upsert_machine(cur, machine: dict, now: str):
    cur.execute("""
        INSERT INTO machines (id, hostname, username, os, os_version, agent_version, fda_granted, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            hostname=VALUES(hostname), username=VALUES(username),
            os=VALUES(os), os_version=VALUES(os_version),
            agent_version=VALUES(agent_version), fda_granted=VALUES(fda_granted),
            last_seen=VALUES(last_seen)
    """, (
        machine.get("machine_id") or str(uuid.uuid5(
            uuid.NAMESPACE_DNS,
            f"{machine.get('hostname','')}:{machine.get('username','')}"
        )),
        machine.get("hostname", ""),
        machine.get("username", ""),
        machine.get("os", ""),
        machine.get("os_version", ""),
        machine.get("agent_version", ""),
        machine.get("fda_granted"),
        now, now,
    ))


def _upsert_finding(cur, machine_id: str, f: dict, now: str):
    import json as _json

    # Merge file_paths: accumulate all locations where this secret appears
    incoming_paths = f.get("file_paths") or [f.get("file_path", "")]
    incoming_paths_json = _json.dumps(list(dict.fromkeys(incoming_paths)))  # dedupe, preserve order

    cur.execute("""
        INSERT INTO findings (
            id, machine_id, pattern_id, pattern_name, severity, category,
            source_type, file_path, file_paths, line_number, value_hash, value_preview,
            context_line, verified_active, ssh_has_passphrase,
            commit_hash, commit_author, commit_date,
            first_seen, last_seen, status
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, 'open'
        )
        ON DUPLICATE KEY UPDATE
            last_seen=VALUES(last_seen),
            verified_active=VALUES(verified_active),
            file_path=VALUES(file_path),
            file_paths=JSON_MERGE_PRESERVE(COALESCE(file_paths, '[]'), VALUES(file_paths))
    """, (
        str(uuid.uuid4()),
        machine_id,
        f.get("pattern_id", ""),
        f.get("pattern_name", ""),
        f.get("severity", "medium"),
        f.get("category", "generic"),
        f.get("source_type", "machine"),
        f.get("file_path", ""),
        incoming_paths_json,
        f.get("line_number"),
        f.get("value_hash", ""),
        _mask(f.get("value_preview", "")),   # redact: never store plaintext
        None,                                 # context_line dropped (leaks the secret line)
        f.get("verified_active"),
        f.get("ssh_has_passphrase"),
        f.get("commit_hash"),
        f.get("commit_author"),
        f.get("commit_date"),
        now, now,
    ))


def _handle_drop_hashes(cur, machine_id: str, drop_hashes: list, now: str):
    if not drop_hashes:
        return
    placeholders = ",".join(["%s"] * len(drop_hashes))
    cur.execute(
        f"""UPDATE findings SET status='rotated', verified_active=0, remediated_at=%s
            WHERE machine_id=%s AND value_hash IN ({placeholders}) AND status='open'""",
        [now, machine_id] + drop_hashes,
    )


def lambda_handler(event, context):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    conn = _get_conn()
    _ensure_tables(conn)

    processed = failed = 0

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
            machine = body.get("machine") or {}
            # `or []` (not the get-default) handles an explicit JSON null, which
            # Go nil slices serialize to. Without this the handler crashed AFTER
            # upserting the machine, so every SQS retry resurrected stale machine
            # rows (old version / root username) forever.
            findings = body.get("findings") or []
            drop_hashes = body.get("drop_hashes") or []

            machine_id = machine.get("machine_id") or str(uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"{machine.get('hostname','')}:{machine.get('username','')}"
            ))

            kept = [f for f in findings if _policy_keep(f)]
            dropped = len(findings) - len(kept)

            with conn.cursor() as cur:
                _upsert_machine(cur, {**machine, "machine_id": machine_id}, now)
                for f in kept:
                    _upsert_finding(cur, machine_id, f, now)
                _handle_drop_hashes(cur, machine_id, drop_hashes, now)

            processed += 1
            logger.info(f"Processed machine={machine.get('hostname')} kept={len(kept)} skipped_inactive={dropped} drops={len(drop_hashes)}")

        except Exception as e:
            # Do NOT re-raise: a malformed/poison record must not block the batch
            # and retry forever (that was what kept re-applying stale rows). Log
            # and move on; the agent re-scans, so no real data is lost.
            logger.error(f"Skipping bad record: {e}")
            failed += 1

    logger.info(f"Batch done: processed={processed} failed={failed}")
    return {"processed": processed, "failed": failed}
