"""Centralized settings for the API process."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SourceID = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]


class ResultReport(BaseModel):
    label: str
    path: Path

    @field_validator("path")
    @classmethod
    def absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("An absolute approved file path is required")
        return value


class ResultSource(BaseModel):
    label: str
    database: Path
    wordlist_provenance: Literal["default", "targeted", "unspecified"] = "unspecified"
    reports: dict[SourceID, ResultReport] = Field(default_factory=dict)

    @field_validator("database")
    @classmethod
    def absolute_database(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("An absolute approved database path is required")
        return value


class Settings(BaseSettings):
    """Environment-backed settings; no credentials are required at startup."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ARGOS_",
        extra="ignore",
    )

    app_name: str = "ARGOS API"
    result_sources: dict[SourceID, ResultSource] = Field(default_factory=dict)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
