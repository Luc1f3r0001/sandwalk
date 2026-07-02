import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request
from server.database import db
from server.models import ScanPayload
from server.auth import require_agent

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _mask(v):
    """Redact a secret to a prefix + last-4 hint ('sk-ant-…MIJS') so plaintext
    never lands in the DB. Must match the consumer Lambda and agent maskValue()."""
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

# Pattern IDs that have live verification — findings with these patterns that are
# unverified (NULL) should not sit in the inventory indefinitely.
VERIFIABLE_PATTERN_IDS = {
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
    "github_pat_classic", "github_pat_fine_grained", "github_oauth_token",
    "github_actions_token", "github_refresh_token",
    "gitlab_pat", "gitlab_deploy_token",
    "slack_bot_token", "slack_user_token",
}


@router.delete("/stale-unverified", status_code=200, dependencies=[Depends(require_agent)])
def drop_stale_unverified(request: Request):
    """
    Purge findings that are leftover from pre-verification scans.
    Only deletes findings NOT updated by the most recent scan (i.e. last_seen is old).
    Findings from the current scan keep their verified_active=NULL — those are
    legitimately unknown (key found but no secret nearby to pair with).
    """
    machine_id = request.headers.get("X-Machine-ID")
    if not machine_id:
        from fastapi import HTTPException  # noqa
        raise HTTPException(400, "X-Machine-ID header required")

    # Get the latest scan time for this machine
    with db() as conn:
        try:
            latest_scan = conn.execute(
                "SELECT scanned_at FROM scans WHERE machine_id=? ORDER BY scanned_at DESC LIMIT 1",
                (machine_id,),
            ).fetchone()
        except Exception:
            latest_scan = None

        if not latest_scan:
            return {"ok": True, "deleted": 0}

        placeholders = ",".join("?" * len(VERIFIABLE_PATTERN_IDS))
        # Only delete findings that were NOT touched by the latest scan
        # (last_seen older than the scan start time = genuine stale leftovers)
        result = conn.execute(
            f"""DELETE FROM findings
                WHERE machine_id=?
                  AND pattern_id IN ({placeholders})
                  AND verified_active IS NULL
                  AND last_seen < ?""",
            [machine_id] + list(VERIFIABLE_PATTERN_IDS) + [latest_scan["scanned_at"]],
        )
    return {"ok": True, "deleted": result.rowcount}


@router.post("", status_code=201, dependencies=[Depends(require_agent)])
def ingest_scan(payload: ScanPayload):
    machine_id = _upsert_machine(payload)
    scan_id = _insert_scan(payload, machine_id)
    _upsert_findings(payload, scan_id, machine_id)
    dropped = _drop_inactive(payload.drop_hashes, machine_id)
    return {"ok": True, "scan_id": scan_id, "machine_id": machine_id, "dropped": dropped}


def _upsert_machine(payload: ScanPayload) -> str:
    m = payload.machine
    machine_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{m.hostname}:{m.username}"))
    now = datetime.now(timezone.utc).isoformat()

    with db() as conn:
        existing = conn.execute("SELECT id FROM machines WHERE id=?", (machine_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE machines SET last_seen=?, os_version=?, agent_version=?, fda_granted=? WHERE id=?",
                (now, m.os_version, m.agent_version, m.fda_granted, machine_id),
            )
        else:
            conn.execute(
                """INSERT INTO machines (id, hostname, username, os, os_version, first_seen, last_seen, agent_version, fda_granted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (machine_id, m.hostname, m.username, m.os, m.os_version, now, now, m.agent_version, m.fda_granted),
            )
    return machine_id


def _insert_scan(payload: ScanPayload, machine_id: str) -> str:
    scan_id = str(uuid.uuid4())
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO scans (id, machine_id, scanned_at, scope, finding_count, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, machine_id, payload.scanned_at, payload.scope,
                 len(payload.findings), payload.duration_ms),
            )
    except Exception:
        pass  # scans table may not exist in MySQL — findings still stored
    return scan_id


def _drop_inactive(drop_hashes: list[str], machine_id: str) -> int:
    """Mark confirmed-inactive credentials as 'rotated' — keep for audit trail, remove from open."""
    if not drop_hashes:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        placeholders = ",".join("?" * len(drop_hashes))
        result = conn.execute(
            f"""UPDATE findings SET status='rotated', verified_active=0, remediated_at=?
                WHERE machine_id=? AND value_hash IN ({placeholders}) AND status='open'""",
            [now, machine_id] + drop_hashes,
        )
        return result.rowcount


def _upsert_findings(payload: ScanPayload, scan_id: str, machine_id: str):
    import json as _json
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        for f in payload.findings:
            # Same value_hash + machine + source_type = same credential, update last_seen
            # source_type is part of the key: git and machine findings for the same secret are separate rows
            existing = conn.execute(
                "SELECT id, file_paths FROM findings WHERE machine_id=? AND value_hash=? AND pattern_id=? AND source_type=?",
                (machine_id, f.value_hash, f.pattern_id, f.source_type),
            ).fetchone()

            if existing:
                # Merge new file_path into the accumulated file_paths JSON array
                paths = _json.loads(existing["file_paths"] or "[]")
                if f.file_path not in paths:
                    paths.append(f.file_path)
                conn.execute(
                    "UPDATE findings SET last_seen=?, scan_id=?, file_path=?, file_paths=?, verified_active=? WHERE id=?",
                    (now, scan_id, f.file_path, _json.dumps(paths), f.verified_active, existing["id"]),
                )
            else:
                finding_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO findings (
                        id, scan_id, machine_id, pattern_id, pattern_name, severity, category,
                        source_type, file_path, file_paths, line_number, value_hash, value_preview, context_line,
                        verified_active, ssh_has_passphrase,
                        commit_hash, commit_author, commit_date,
                        first_seen, last_seen, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
                    (
                        finding_id, scan_id, machine_id,
                        f.pattern_id, f.pattern_name, f.severity, f.category,
                        f.source_type,
                        f.file_path, _json.dumps([f.file_path]),
                        f.line_number, f.value_hash, _mask(f.value_preview),
                        None, f.verified_active, f.ssh_has_passphrase,
                        getattr(f, 'commit_hash', None),
                        getattr(f, 'commit_author', None),
                        getattr(f, 'commit_date', None),
                        now, now,
                    ),
                )
