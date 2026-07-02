"""
Sandwalk — single server.
  • Agents POST to /api/scans (authenticated with X-Agent-Key header)
  • Admin views dashboard at / (authenticated with HTTP Basic Auth)
  • No separate frontend dev server needed — dashboard is built once and served here.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from server.database import init_db
from server.routers import scans, findings, machines, export, rescan

DASHBOARD_DIST = Path(__file__).parent.parent / "dashboard" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("Database initialised.")
    if not DASHBOARD_DIST.exists():
        print(
            "WARNING: dashboard/dist/ not found. "
            "Run `cd dashboard && bun run build` to build the admin UI."
        )
    yield


app = FastAPI(
    title="Sandwalk",
    version="1.0.0",
    docs_url=None,      # disable public Swagger UI
    redoc_url=None,
    lifespan=lifespan,
)

# ── Health check (ECS/ALB) ───────────────────────────────────────────────────
@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(scans.router)       # POST /api/scans              — agent upload (agent key)
app.include_router(findings.router)    # GET  /api/findings           — admin only
app.include_router(machines.router)    # GET  /api/machines           — admin only
app.include_router(export.router)      # GET  /api/export/*           — admin only
app.include_router(rescan.router)      # POST /api/machines/{id}/rescan — admin; GET /api/rescan/pending — agent

# ── Serve built dashboard (admin UI) ─────────────────────────────────────────
# Mount after all API routes so /api/* is matched first.
# html=True makes StaticFiles serve index.html for unknown paths (SPA routing).
if DASHBOARD_DIST.exists():
    # Explicit SPA catch-all — serves index.html for all non-API paths so
    # React Router works on direct URL / page refresh.
    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        index = DASHBOARD_DIST / "index.html"
        # Serve actual static assets directly, fall back to index.html for routes
        asset = DASHBOARD_DIST / full_path
        if asset.exists() and asset.is_file():
            return FileResponse(str(asset))
        return FileResponse(str(index))

    app.mount(
        "/assets",
        StaticFiles(directory=str(DASHBOARD_DIST / "assets")),
        name="assets",
    )
else:
    @app.get("/", include_in_schema=False)
    def no_ui():
        return HTMLResponse(
            "<h2>Dashboard not built.</h2>"
            "<p>Run <code>cd dashboard && bun run build</code> then restart the server.</p>"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("server.main:app", host=host, port=port, reload=False)
