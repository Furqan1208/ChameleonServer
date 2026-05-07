# D:\FYP\ChameleonServer\app\main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.controllers import ml_routes

from app.controllers.analysis_routes import router as analysis_router
from app.controllers.auth_routes import router as auth_router
from app.controllers.threat_intel_routes import router as threat_intel_router
from app.controllers.user_routes import router as user_router
from app.database.mongodb import lifespan

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
    allow_credentials=True,
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


@app.get("/")
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
