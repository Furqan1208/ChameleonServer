# D:\FYP\ChameleonServer\app\main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.controllers import ml_routes

from app.controllers.analysis_routes import router as analysis_router
from app.controllers.auth_routes import router as auth_router
from app.controllers.threat_intel_routes import router as threat_intel_router
from app.controllers.user_routes import router as user_router
from app.database.mongodb import lifespan
from app.utils.logger import get_logger

_logger = get_logger("app.main")

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Chameleon AI Malware Analysis Server",
    description="Enhanced malware analysis with AI-powered progressive analysis and chunking",
    version="2.0.0",
    lifespan=lifespan,
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, specify your frontend URL
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(user_router)
app.include_router(auth_router)
app.include_router(analysis_router)
app.include_router(threat_intel_router)
# ADDED_ML: Register optional ML routes under /api/ml namespace.
app.include_router(ml_routes.router, prefix="/api/ml", tags=["ML"])

# ADDED_ML: Initialize optional scheduler for 6-hour retrain checks.
try:
    from app.ml.scheduler import initialize_ml_scheduler

    initialize_ml_scheduler(app)
except Exception:
    # ADDED_ML: ML scheduler failure must not affect core platform availability.
    pass


# Global exception handler for unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions and log them"""
    _logger.exception(
        "Unhandled exception in %s %s: %s",
        request.method,
        request.url.path,
        str(exc),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# Exception handler for HTTPException (FastAPI's version)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Log HTTP exceptions for audit/debugging"""
    if exc.status_code >= 500:
        _logger.error(
            "HTTP %d in %s %s: %s",
            exc.status_code,
            request.method,
            request.url.path,
            exc.detail,
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
async def root():
    return {
        "message": "Welcome to Chameleon AI Malware Analysis Server",
        "version": "2.0.0",
        "features": [
            "Enhanced progressive analysis with chunking",
            "Multi-model AI with automatic fallback",
            "Behavior and strings section chunking",
            "Robust error recovery and model tracking",
            "Comprehensive malware analysis pipeline",
        ],
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Chameleon AI Malware Analysis",
        "version": "2.0.0",
    }


@app.get("/models")
async def get_available_models():
    """Get available AI models"""
    # This would need to be implemented with proper dependency injection
    return {
        "message": "Model list available via /analysis/model-stats endpoint",
        "note": "Use the enhanced analysis endpoints for model information",
    }
