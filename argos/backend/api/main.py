"""FastAPI application composition root."""

from fastapi import FastAPI, Request

from argos.backend.api.routes.health import router as health_router
from argos.backend.api.routes.results import results_router
from argos.backend.core.config import Settings, get_settings
from argos.backend.core.errors import install_error_handlers


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the API without starting any domain or execution workflows."""
    app_settings = settings or get_settings()
    app = FastAPI(title=app_settings.app_name, version="0.1.0")
    install_error_handlers(app)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(results_router(app_settings), prefix="/api/v1")

    @app.middleware("http")
    async def private_results(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/v1/results"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    return app


app = create_app()
