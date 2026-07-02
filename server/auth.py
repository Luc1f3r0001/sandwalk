"""
Auth for the Sandwalk server.

Two principals:
  - Admin: HTTP Basic Auth (ADMIN_USER / ADMIN_PASSWORD env vars)
            → can read/write all dashboard API routes
  - Agent: X-Agent-Key header (AGENT_KEY env var)
            → can only POST /api/scans (upload scan results)
"""
import os
import secrets
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
AGENT_KEY = os.getenv("AGENT_KEY", "default-agent-key")

_basic = HTTPBasic(auto_error=False)


def require_admin(credentials: HTTPBasicCredentials = Depends(_basic)):
    """FastAPI dependency — enforce admin Basic Auth."""
    ok = credentials is not None
    if ok:
        ok = (
            secrets.compare_digest(credentials.username.encode(), ADMIN_USER.encode())
            and secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
        )
    if not ok:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="Sandwalk"'},
        )


def require_agent(request: Request):
    """FastAPI dependency — enforce agent API key."""
    key = request.headers.get("X-Agent-Key", "")
    if not secrets.compare_digest(key.encode(), AGENT_KEY.encode()):
        raise HTTPException(status_code=403, detail="Invalid agent key")
