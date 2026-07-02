from fastapi import APIRouter, Depends
from server.database import db
from server.models import MachineOut
from server.auth import require_admin

router = APIRouter(prefix="/api/machines", tags=["machines"], dependencies=[Depends(require_admin)])


@router.get("", response_model=list[MachineOut])
def list_machines():
    with db() as conn:
        rows = conn.execute(
            """SELECT
                m.*,
                0 as scan_count,
                SUM(CASE WHEN f.severity='critical' AND f.status='open' THEN 1 ELSE 0 END) as open_critical,
                SUM(CASE WHEN f.severity='high'     AND f.status='open' THEN 1 ELSE 0 END) as open_high,
                SUM(CASE WHEN f.severity='medium'   AND f.status='open' THEN 1 ELSE 0 END) as open_medium,
                SUM(CASE WHEN f.severity='low'      AND f.status='open' THEN 1 ELSE 0 END) as open_low,
                SUM(CASE WHEN f.status='open' THEN 1 ELSE 0 END) as total_open
               FROM machines m
               LEFT JOIN findings f ON f.machine_id = m.id
               GROUP BY m.id
               ORDER BY m.last_seen DESC"""
        ).fetchall()

    return [
        MachineOut(
            id=r["id"],
            hostname=r["hostname"],
            username=r["username"],
            os=r["os"] or "",
            first_seen=str(r["first_seen"]),
            last_seen=str(r["last_seen"]),
            scan_count=r["scan_count"] or 0,
            open_critical=r["open_critical"] or 0,
            open_high=r["open_high"] or 0,
            open_medium=r["open_medium"] or 0,
            open_low=r["open_low"] or 0,
            total_open=r["total_open"] or 0,
            agent_version=r["agent_version"] if "agent_version" in r.keys() else None,
            fda_granted=(r["fda_granted"] if "fda_granted" in r.keys() else None),
        )
        for r in rows
        if r["hostname"]  # skip blank hostname entries
    ]


@router.get("/{machine_id}")
def get_machine(machine_id: str):
    with db() as conn:
        machine = conn.execute("SELECT * FROM machines WHERE id=?", (machine_id,)).fetchone()
        try:
            scans = conn.execute(
                "SELECT * FROM scans WHERE machine_id=? ORDER BY scanned_at DESC LIMIT 20",
                (machine_id,),
            ).fetchall()
        except Exception:
            scans = []

    if not machine:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Machine not found")

    with db() as conn:
        stats = conn.execute(
            """SELECT
                SUM(CASE WHEN status IN ('open','removed_active') THEN 1 ELSE 0 END) as open_findings,
                SUM(CASE WHEN verified_active=1 AND status IN ('open','removed_active') THEN 1 ELSE 0 END) as confirmed_active,
                SUM(CASE WHEN status='removed_active' THEN 1 ELSE 0 END) as removed_active
               FROM findings WHERE machine_id=?""",
            (machine_id,),
        ).fetchone()

    m = dict(machine)
    m["open_findings"] = (stats["open_findings"] or 0) if stats else 0
    m["confirmed_active"] = (stats["confirmed_active"] or 0) if stats else 0
    m["removed_active"] = (stats["removed_active"] or 0) if stats else 0

    return {
        "machine": m,
        "recent_scans": [dict(s) for s in scans],
    }


@router.delete("/cleanup/blank")
def cleanup_blank_machines():
    """Delete machines with blank/null hostname (junk registrations) and their findings."""
    with db() as conn:
        rows = conn.execute(
            "SELECT id FROM machines WHERE hostname IS NULL OR hostname = ''"
        ).fetchall()
        ids = [r["id"] for r in rows]
        for mid in ids:
            conn.execute("DELETE FROM findings WHERE machine_id=?", (mid,))
            conn.execute("DELETE FROM machines WHERE id=?", (mid,))
    return {"ok": True, "deleted": ids}


@router.delete("/{machine_id}")
def delete_machine(machine_id: str):
    with db() as conn:
        conn.execute("DELETE FROM findings WHERE machine_id=?", (machine_id,))
        conn.execute("DELETE FROM machines WHERE id=?", (machine_id,))
    return {"ok": True}


@router.post("/{machine_id}/validate-all")
def validate_all(machine_id: str):
    """Re-validate ON THE DEVICE. The DB no longer holds plaintext (redacted to a
    last-4 hint), so the server cannot validate — only the endpoint can, where the
    secret still lives in its file. This dispatches a full rescan; the agent
    re-scans and re-validates every secret and reports fresh verdicts (active kept,
    rotated closed). The dashboard's badge + last_seen reflect the result."""
    import uuid
    from datetime import datetime, timezone
    from fastapi import HTTPException

    with db() as conn:
        if not conn.execute("SELECT id FROM machines WHERE id=?", (machine_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Machine not found")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE rescan_requests SET status='cancelled' WHERE machine_id=? AND status='pending'",
            (machine_id,),
        )
        rid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO rescan_requests (id, machine_id, requested_at, scope, status) VALUES (?,?,?,?,'pending')",
            (rid, machine_id, now, "full"),
        )
    return {
        "dispatched": True,
        "request_id": rid,
        "message": "Re-validation scan dispatched to the device — verdicts refresh as it completes.",
    }
