from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Upstream API configuration
    upstream_base: str = Field(
        default="https://api.openai.com",
        description="Base URL for upstream API"
    )
    upstream_auth: str = Field(
        default="",
        description="Authorization header value for upstream"
    )

    # Detection thresholds
    min_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score to mask an entity"
    )

    # Feature flags
    enable_presidio: bool = Field(
        default=True,
        description="Enable Microsoft Presidio detectors"
    )
    enable_audit_log: bool = Field(
        default=True,
        description="Enable compliance audit logging"
    )
    enable_streaming: bool = Field(
        default=True,
        description="Enable SSE streaming support"
    )

    # Performance
    cache_ttl_seconds: int = Field(
        default=300,
        description="TTL for detection cache entries"
    )
    max_request_size_mb: int = Field(
        default=10,
        description="Maximum request body size in MB"
    )

    # Audit endpoint security
    audit_api_key: str = Field(
        default="",
        description="API key required for /audit/* endpoints. Empty = no auth (dev only)."
    )

    # Paths
    entities_config_path: str = Field(
        default="config/entities.yaml",
        description="Path to custom entities YAML"
    )
    audit_db_path: str = Field(
        default="audit.db",
        description="Path to SQLite audit database"
    )

    class Config:
        env_prefix = "PROXY_"
        env_file = ".env"


settings = Settings()
