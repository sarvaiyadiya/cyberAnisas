"""
main.py

ANISAS — Advanced Network Intelligence & Security Analysis System.

FastAPI application entry point.

Architecture:
  Routes are registered via APIRouter objects defined in api/v1/.
  No business logic lives in this file.
"""

from fastapi import FastAPI
from app.core.config import settings
from app.core.logger import get_logger
from app.api.v1.asn import router as asn_router
from app.api.v1.iot import router as iot_router
from app.api.v1.wireless import router as wireless_router

logger = get_logger(__name__)

# ── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ── Register module routers ───────────────────────────────────────────────────
app.include_router(asn_router, prefix=settings.API_V1_PREFIX)
app.include_router(iot_router, prefix=settings.API_V1_PREFIX)
app.include_router(wireless_router, prefix=settings.API_V1_PREFIX)

# Future modules registered here — no changes to existing routes needed:
# app.include_router(network_recon_router, prefix=settings.API_V1_PREFIX)
# app.include_router(security_router,      prefix=settings.API_V1_PREFIX)
# app.include_router(wireless_router,      prefix=settings.API_V1_PREFIX)
# app.include_router(ai_router,            prefix=settings.API_V1_PREFIX)


# ── Health check ─────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="Health check")
def health_check() -> dict:
    """Returns application status and version."""
    return {
        "success": True,
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
    }


logger.info("%s v%s started.", settings.APP_NAME, settings.APP_VERSION)
