import csv
import io
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse, PlainTextResponse
from server.database import db
from server.auth import require_admin

router = APIRouter(prefix="/api/export", tags=["export"], dependencies=[Depends(require_admin)])


@router.get("/csv")
def export_csv(status: str = "open"):
    with db() as conn:
        rows = conn.execute(
            """SELECT f.*, m.hostname, m.username
               FROM findings f JOIN machines m ON m.id = f.machine_id
               WHERE f.status = ?
               ORDER BY f.severity, f.first_seen""",
            (status,),
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Hostname", "Username", "Pattern", "Severity", "Category",
        "File Path", "Line", "Value Preview", "Verified Active",
        "SSH Has Passphrase", "Status", "First Seen", "Last Seen", "Notes",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["hostname"], r["username"], r["pattern_name"],
            r["severity"], r["category"], r["file_path"], r["line_number"],
            r["value_preview"],
            "yes" if r["verified_active"] else ("no" if r["verified_active"] is not None else "unknown"),
            "yes" if r["ssh_has_passphrase"] else ("no" if r["ssh_has_passphrase"] is not None else "N/A"),
            r["status"], r["first_seen"], r["last_seen"], r["notes"] or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{status}.csv"},
    )


@router.get("/sarif")
def export_sarif():
    """Export findings in SARIF 2.1.0 format for SIEM / security tooling."""
    with db() as conn:
        rows = conn.execute(
            """SELECT f.*, m.hostname, m.username
               FROM findings f JOIN machines m ON m.id = f.machine_id
               WHERE f.status = 'open'"""
        ).fetchall()

    SEVERITY_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

    results = []
    for r in rows:
        results.append({
            "ruleId": r["pattern_id"],
            "level": SEVERITY_MAP.get(r["severity"], "warning"),
            "message": {"text": f"{r['pattern_name']} found on {r['hostname']} ({r['username']})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r["file_path"]},
                    "region": {"startLine": r["line_number"] or 1},
                }
            }],
            "properties": {
                "machine": r["hostname"],
                "username": r["username"],
                "category": r["category"],
                "severity": r["severity"],
                "valuePreview": r["value_preview"],
                "verifiedActive": r["verified_active"],
                "firstSeen": r["first_seen"],
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sandwalk",
                    "version": "1.0.0",
                    "rules": [],
                }
            },
            "results": results,
        }],
    }

    import json
    return PlainTextResponse(
        content=json.dumps(sarif, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.sarif.json"},
    )
