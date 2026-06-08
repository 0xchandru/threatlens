from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database import init_db
from app.api.v1 import ioc, dashboard, search, reports
import os

app = FastAPI(
    title="ThreatLens API",
    description="SOC Threat Intelligence Aggregator",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()


app.include_router(ioc.router,       prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(search.router,    prefix="/api/v1")
app.include_router(reports.router,   prefix="/api/v1")


@app.get("/health")
def health():
    return {"status": "ok", "service": "ThreatLens"}


STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")

if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        index = os.path.join(STATIC_DIR, "index.html")
        return FileResponse(index)
