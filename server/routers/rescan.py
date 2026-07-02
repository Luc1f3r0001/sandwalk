"""
Rescan request routes.

Admin flow:  POST /api/machines/{id}/rescan   → creates a pending request
Agent flow:  GET  /api/rescan/pending          → agent polls this; returns request if one exists
             POST /api/rescan/{id}/fulfill     → agent marks request done after uploading scan
"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from server.database import db
from server.auth import require_admin, require_agent
from pydantic import BaseModel

router = APIRouter(tags=["rescan"])


class RescanRequest(BaseModel):
    scope: str = "standard"


# ── Admin: request a rescan ───────────────────────────────────────────────────

@router.post("/api/machines/{machine_id}/rescan", dependencies=[Depends(require_admin)])
def request_rescan(machine_id: str, body: RescanRequest = RescanRequest()):
    """Admin requests a rescan of a specific machine. Agent picks this up on next poll."""
    with db() as conn:
        machine = conn.execute("SELECT id FROM machines WHERE id=?", (machine_id,)).fetchone()
        if not machine:
            raise HTTPException(status_code=404, detail="Machine not found")

        # Cancel any existing pending request for this machine before creating a new one
        conn.execute(
            "UPDATE rescan_requests SET status='cancelled' WHERE machine_id=? AND status='pending'",
            (machine_id,),
        )

        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO rescan_requests (id, machine_id, requested_at, scope, status) VALUES (?,?,?,?,'pending')",
            (request_id, machine_id, now, body.scope),
        )

    return {"ok": True, "request_id": request_id}


@router.get("/api/machines/{machine_id}/rescan-status", dependencies=[Depends(require_admin)])
def rescan_status(machine_id: str):
    """Returns the latest rescan request status for a machine."""
    with db() as conn:
        row = conn.execute(
            """SELECT * FROM rescan_requests WHERE machine_id=?
               ORDER BY requested_at DESC LIMIT 1""",
            (machine_id,),
        ).fetchone()
    if not row:
        return {"status": "none"}
    return dict(row)


# ── Agent: poll for pending request ──────────────────────────────────────────

@router.get("/api/rescan/pending", dependencies=[Depends(require_agent)])
def poll_pending(request: Request):
    """
    Agent calls this on each watch-loop iteration.
    Requires X-Machine-ID header (the machine's UUID, returned from first scan upload).
    Returns the pending rescan request if one exists, else null.
    """
    machine_id = request.headers.get("X-Machine-ID")
    if not machine_id:
        raise HTTPException(status_code=400, detail="X-Machine-ID header required")

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM rescan_requests WHERE machine_id=? AND status='pending' ORDER BY requested_at LIMIT 1",
            (machine_id,),
        ).fetchone()

    if not row:
        return {"pending": False}

    return {"pending": True, "request_id": row["id"], "scope": row["scope"], "requested_at": row["requested_at"]}


@router.post("/api/rescan/{request_id}/fulfill", dependencies=[Depends(require_agent)])
def fulfill_rescan(request_id: str):
    """Agent calls this after completing a scan to mark the request as fulfilled."""
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            "UPDATE rescan_requests SET status='fulfilled', fulfilled_at=? WHERE id=?",
            (now, request_id),
        )
    return {"ok": True}
