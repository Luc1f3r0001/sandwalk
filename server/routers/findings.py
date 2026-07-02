import re
from datetime import datetime, timezone
from fastapi import APIRouter, Query, Depends
from typing import Optional
from server.database import db
from server.models import FindingOut, FindingUpdate
from server.auth import require_admin

router = APIRouter(prefix="/api/findings", tags=["findings"], dependencies=[Depends(require_admin)])

# validate-or-remove policy: only confirmed-active secrets are flagged. SSH/TLS
# private keys have no network validator, so the machine owner's OWN ~/.ssh keys
# are the sole exception — kept without validation; private keys anywhere else
# are noise.
_SSH_OWN_RE = re.compile(r'(/Users/[^/]+|/home/[^/]+|/var/root|/root)/\.ssh/')


def _is_own_ssh_key(row) -> bool:
    try:
        return row["pattern_id"] == "ssh_private_key" and bool(_SSH_OWN_RE.search(row["file_path"] or ""))
    except (KeyError, IndexError, TypeError):
        return False


@router.get("", response_model=list[FindingOut])
def list_findings(
    machine_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    verified: Optional[str] = Query(None),  # 'true' | 'false' | 'null'
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
):
    clauses = []
    params = []

    if machine_id:
        clauses.append("f.machine_id = ?")
        params.append(machine_id)
    if severity:
        clauses.append("f.severity = ?")
        params.append(severity)
    if status:
        clauses.append("f.status = ?")
        params.append(status)
    if category:
        clauses.append("f.category = ?")
        params.append(category)
    if source_type:
        clauses.append("f.source_type = ?")
        params.append(source_type)
    if verified == "true":
        clauses.append("f.verified_active = 1")
    elif verified == "false":
        clauses.append("f.verified_active = 0")
    elif verified == "null":
        clauses.append("f.verified_active IS NULL")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([limit, offset])

    with db() as conn:
        rows = conn.execute(
            f"""SELECT f.*, m.hostname, m.username
                FROM findings f
                LEFT JOIN machines m ON m.id = f.machine_id
                {where}
                ORDER BY
                    CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                                    WHEN 'medium' THEN 3 ELSE 4 END,
                    f.first_seen DESC
                LIMIT ? OFFSET ?""",
            params,
        ).fetchall()

    return [_row_to_finding(r) for r in rows]


@router.patch("/{finding_id}")
def update_finding(finding_id: str, update: FindingUpdate):
    now = datetime.now(timezone.utc).isoformat()
    remediated_at = now if update.status in ("fixed", "excepted", "false_positive") else None

    with db() as conn:
        conn.execute(
            "UPDATE findings SET status=?, notes=?, remediated_at=? WHERE id=?",
            (update.status, update.notes, remediated_at, finding_id),
        )
    return {"ok": True}


@router.delete("/purge-inactive-patterns")
def purge_inactive_patterns(active_pattern_ids: str):
    """Delete all findings whose pattern_id is not in the active set. Called by daemon on startup."""
    active = set(p.strip() for p in active_pattern_ids.split(",") if p.strip())
    with db() as conn:
        rows = conn.execute("SELECT DISTINCT pattern_id FROM findings").fetchall()
        inactive = [r["pattern_id"] for r in rows if r["pattern_id"] not in active]
        deleted = 0
        for pid in inactive:
            cur = conn.execute("DELETE FROM findings WHERE pattern_id=?", (pid,))
            deleted += cur.rowcount
    return {"purged_patterns": inactive, "deleted_findings": deleted}


@router.post("/mark-active")
def mark_active(payload: dict):
    """Mark findings as verified active (confirmed live credential)."""
    machine_id = payload.get("machine_id", "")
    hashes = payload.get("value_hashes", [])
    if not hashes:
        return {"updated": 0}
    placeholders = ",".join("?" * len(hashes))
    with db() as conn:
        result = conn.execute(
            f"UPDATE findings SET verified_active=1 WHERE machine_id=? AND value_hash IN ({placeholders})",
            [machine_id] + hashes,
        )
    return {"updated": result.rowcount}


def _validate_finding(row) -> Optional[bool]:
    """Validate one finding's value via Kingfisher, pairing AWS key IDs from the same file."""
    from server import kf
    aws_key_id = None
    if row["pattern_id"] == "aws_secret_access_key":
        with db() as conn:
            companion = conn.execute(
                "SELECT value_preview FROM findings WHERE pattern_id='aws_access_key_id' AND file_path=? AND status IN ('open','removed_active') LIMIT 1",
                (row["file_path"],)
            ).fetchone()
        if companion:
            aws_key_id = companion["value_preview"]
    return kf.validate(row["pattern_id"], row["value_preview"], aws_key_id=aws_key_id)


@router.post("/{finding_id}/verify")
def reverify_finding(finding_id: str):
    """Re-check liveness ON THE DEVICE. The server no longer stores plaintext
    (redacted to a last-4 hint), so it cannot validate — it dispatches a rescan
    for this finding's machine and the agent re-validates locally, reporting the
    fresh verdict (active kept, rotated closed)."""
    import uuid
    from datetime import datetime, timezone
    from fastapi import HTTPException
    with db() as conn:
        row = conn.execute("SELECT machine_id FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")
        mid = row["machine_id"]
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE rescan_requests SET status='cancelled' WHERE machine_id=? AND status='pending'",
            (mid,),
        )
        rid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO rescan_requests (id, machine_id, requested_at, scope, status) VALUES (?,?,?,?,'pending')",
            (rid, mid, now, "full"),
        )
    return {"dispatched": True, "message": "Re-validation scan dispatched to the device."}


@router.post("/mark-fixed")
def mark_fixed(payload: dict):
    """Agent reports secrets removed from a file and confirmed rotated/gone."""
    from datetime import datetime, timezone
    machine_id = payload.get("machine_id")
    hashes = payload.get("value_hashes", [])
    if not machine_id or not hashes:
        return {"updated": 0}
    now = datetime.now(timezone.utc).isoformat()
    ph = ",".join("?" * len(hashes))
    with db() as conn:
        r = conn.execute(
            f"UPDATE findings SET status='fixed', remediated_at=? WHERE machine_id=? AND value_hash IN ({ph}) AND status IN ('open','removed_active')",
            [now, machine_id] + hashes,
        )
    return {"updated": r.rowcount}


@router.delete("/clear-all")
def clear_all_findings():
    """Wipe ALL findings across every machine for a fresh start. Machines stay registered."""
    with db() as conn:
        r = conn.execute("DELETE FROM findings")
        try:
            conn.execute("UPDATE machines SET scan_count=0")
        except Exception:
            pass
    return {"ok": True, "deleted": r.rowcount}


@router.delete("/non-active")
def delete_non_active():
    """validate-or-remove cleanup across ALL machines: delete every finding that
    is not confirmed active (verified_active != 1), EXCEPT the machine owner's
    own ~/.ssh private keys. Uses the verified_active recorded at scan time — no
    re-validation — so it is fast and idempotent."""
    from server.database import DB_ENGINE
    ssh_re = r'(/Users/[^/]+|/home/[^/]+|/var/root|/root)/\.ssh/'
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        if DB_ENGINE == "mysql":
            conn.execute(
                "DELETE FROM findings "
                "WHERE (verified_active IS NULL OR verified_active <> 1) "
                "   OR (pattern_id='ssh_private_key' AND file_path NOT REGEXP ?)",
                (ssh_re,),
            )
        else:  # sqlite dev — no REGEXP; filter in Python
            rx = re.compile(ssh_re)
            rows = conn.execute("SELECT id, pattern_id, file_path, verified_active FROM findings").fetchall()
            for row in rows:
                keep = row["verified_active"] == 1 and (
                    row["pattern_id"] != "ssh_private_key" or bool(rx.search(row["file_path"] or ""))
                )
                if not keep:
                    conn.execute("DELETE FROM findings WHERE id=?", (row["id"],))
        after = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    return {"deleted": before - after, "remaining": after}


@router.post("/mark-removed-active")
def mark_removed_active(payload: dict):
    """Secret was removed from its file but is still LIVE — distinct 'removed_active' tag."""
    machine_id = payload.get("machine_id")
    hashes = payload.get("value_hashes", [])
    if not machine_id or not hashes:
        return {"updated": 0}
    ph = ",".join("?" * len(hashes))
    with db() as conn:
        r = conn.execute(
            f"UPDATE findings SET status='removed_active', verified_active=1 WHERE machine_id=? AND value_hash IN ({ph}) AND status IN ('open','removed_active')",
            [machine_id] + hashes,
        )
    return {"updated": r.rowcount}


@router.get("/stats")
def get_stats():
    with db() as conn:
        # All open findings (active + unverified) — used for main counts
        sev_all = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE status='open' GROUP BY severity"
        ).fetchall()
        sev_active = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE status='open' AND verified_active=1 GROUP BY severity"
        ).fetchall()
        sev_unverified = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE status='open' AND verified_active IS NULL GROUP BY severity"
        ).fetchall()
        category_rows = conn.execute(
            "SELECT category, COUNT(*) as count FROM findings WHERE status='open' GROUP BY category ORDER BY count DESC"
        ).fetchall()
        unverified_category = conn.execute(
            "SELECT category, COUNT(*) as count FROM findings WHERE status='open' AND verified_active IS NULL GROUP BY category ORDER BY count DESC"
        ).fetchall()
        type_rows = conn.execute(
            "SELECT pattern_name, COUNT(*) as count FROM findings WHERE status='open' GROUP BY pattern_name ORDER BY count DESC LIMIT 10"
        ).fetchall()
        source_rows = conn.execute(
            "SELECT source_type, COUNT(*) as count FROM findings WHERE status='open' GROUP BY source_type"
        ).fetchall()
        rotated_count = conn.execute("SELECT COUNT(*) FROM findings WHERE status='rotated'").fetchone()[0]
        machine_count = conn.execute(
            "SELECT COUNT(*) FROM machines WHERE hostname IS NOT NULL AND hostname != ''"
        ).fetchone()[0]
        try:
            from server.database import DB_ENGINE
            if DB_ENGINE == "mysql":
                date_expr = "DATE_SUB(NOW(), INTERVAL 7 DAY)"
            else:
                date_expr = "datetime('now', '-7 days')"
            scanned_7d = conn.execute(
                f"SELECT COUNT(DISTINCT machine_id) FROM scans WHERE scanned_at > {date_expr}"
            ).fetchone()[0]
        except Exception:
            scanned_7d = machine_count  # fallback: all machines

    all_sev    = {r["severity"]: r["count"] for r in sev_all}
    active_sev = {r["severity"]: r["count"] for r in sev_active}
    unver_sev  = {r["severity"]: r["count"] for r in sev_unverified}
    source_map = {r["source_type"]: r["count"] for r in source_rows}

    return {
        "total_machines": machine_count,
        "scanned_last_7d": scanned_7d,
        # Total open (active + unverified) — main dashboard numbers
        "open_findings": sum(all_sev.values()),
        "critical_findings": all_sev.get("critical", 0),
        "high_findings": all_sev.get("high", 0),
        "medium_findings": all_sev.get("medium", 0),
        "low_findings": all_sev.get("low", 0),
        "machine_findings": source_map.get("machine", 0),
        "git_findings": source_map.get("git", 0),
        # Verification breakdown
        "confirmed_active": sum(active_sev.values()),
        "active_critical": active_sev.get("critical", 0),
        "active_high": active_sev.get("high", 0),
        "unverified_count": sum(unver_sev.values()),
        "unverified_critical": unver_sev.get("critical", 0),
        "rotated_count": rotated_count,
        "findings_by_category": {r["category"]: r["count"] for r in category_rows},
        "unverified_by_category": {r["category"]: r["count"] for r in unverified_category},
        "top_finding_types": [{"name": r["pattern_name"], "count": r["count"]} for r in type_rows],
    }


def _row_to_finding(r) -> FindingOut:
    from server.patterns_meta import PATTERNS
    _pattern_map = {p.id: p for p in PATTERNS}
    pat = _pattern_map.get(r["pattern_id"])
    def _get(key, default=None):
        try:
            v = r[key]
            return v if v is not None else default
        except (KeyError, IndexError):
            return default

    return FindingOut(
        id=_get("id", ""),
        scan_id=_get("scan_id"),
        machine_id=_get("machine_id", ""),
        hostname=_get("hostname", ""),
        username=_get("username", ""),
        pattern_id=_get("pattern_id", ""),
        pattern_name=_get("pattern_name", ""),
        severity=_get("severity", "medium"),
        category=_get("category", "generic"),
        source_type=_get("source_type") or "machine",
        file_path=_get("file_path", ""),
        file_paths=list(dict.fromkeys(__import__("json").loads(_get("file_paths") or "[]"))) or None,
        line_number=_get("line_number"),
        value_hash=_get("value_hash", ""),
        value_preview=_get("value_preview", ""),
        context_line=_get("context_line"),
        verified_active=bool(_get("verified_active")) if _get("verified_active") is not None else None,
        ssh_has_passphrase=bool(_get("ssh_has_passphrase")) if _get("ssh_has_passphrase") is not None else None,
        first_seen=str(_get("first_seen", "")),
        last_seen=str(_get("last_seen", "")),
        status=_get("status", "open"),
        remediated_at=str(_get("remediated_at")) if _get("remediated_at") else None,
        notes=_get("notes"),
        commit_hash=_get("commit_hash"),
        commit_author=_get("commit_author"),
        commit_date=str(_get("commit_date")) if _get("commit_date") else None,
        blast_radius=pat.blast_radius if pat else None,
        remediation=pat.remediation if pat else None,
    )
