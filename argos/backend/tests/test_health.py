import pytest
from argos.backend.api.main import create_app
from argos.backend.core.config import Settings
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic_settings import SettingsConfigDict


class IsolatedSettings(Settings):
    """Do not load a developer's .env when exercising the API."""

    model_config = SettingsConfigDict(env_file=None)


@pytest.mark.anyio
async def test_http_errors_preserve_status_and_retry_headers() -> None:
    app = create_app(IsolatedSettings())

    @app.get("/limited")
    def limited() -> None:
        raise HTTPException(429, "Try again later", headers={"Retry-After": "30"})

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/limited")

    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
    assert response.json() == {
        "error": {"code": "http_error", "message": "Try again later"}
    }


@pytest.mark.anyio
async def test_validation_errors_do_not_return_submitted_values() -> None:
    app = create_app(IsolatedSettings())

    @app.get("/typed")
    def typed(value: int) -> dict[str, int]:
        return {"value": value}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/typed", params={"value": "PRIVATE_INPUT"})

    assert response.status_code == 422
    assert response.json() == {
        "error": {"code": "invalid_request", "message": "Request validation failed."}
    }
    assert "PRIVATE_INPUT" not in response.text


@pytest.mark.anyio
async def test_health_reports_only_service_status() -> None:
    app = create_app(IsolatedSettings())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_unknown_routes_use_the_stable_error_shape() -> None:
    app = create_app(IsolatedSettings())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/api/v1/not-found")

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "http_error", "message": "Not Found"}
    }


@pytest.mark.anyio
async def test_post_to_health_is_not_an_allowed_operation() -> None:
    app = create_app(IsolatedSettings())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/api/v1/health", json={"secret": "not-returned"}
        )

    assert response.status_code == 405
    assert response.json() == {
        "error": {"code": "http_error", "message": "Method Not Allowed"}
    }
    assert "not-returned" not in response.text
