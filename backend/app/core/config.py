import json
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    env: str = "development"
    database_url: str = "postgresql+psycopg://gatepass:devpass@127.0.0.1:5432/gatepass_dev"
    secret_key: str = "dev-only-secret-change-me-dev-only-secret-change-me"
    app_encryption_key: str = "dev-only-encryption-key-change-me-0000"   # used for MFA secret encryption
    access_token_minutes: int = 15
    refresh_token_days: int = 14
    setup_token_minutes: int = 10
    cors_origins: str = "http://localhost:3000,https://localhost,capacitor://localhost,app://-"
    storage_backend: str = "local"            # local | s3
    local_storage_dir: str = "./storage_data"
    s3_endpoint: str | None = None
    s3_public_endpoint: str | None = None
    s3_region: str = "us-east-1"
    s3_bucket: str = "gatepass-files"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_force_path_style: bool = True
    public_base_url: str = "http://localhost:8000"   # used for local-storage presigned URLs
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "gatepass@mtj-clothing.local"
    smtp_starttls: bool = True
    timezone: str = "Asia/Karachi"
    docs_enabled: bool = True
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 65536

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @field_validator("secret_key")
    @classmethod
    def _len(cls, v):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    def assert_production_safe(self):
        if self.env == "production":
            weak = ("dev-only", "CHANGE_ME", "generate-", "test-")
            if self.secret_key.startswith(weak) or self.app_encryption_key.startswith(weak):
                raise RuntimeError("Refusing to start in production with development secrets")
            if "localhost" in self.database_url and self.env == "production":
                pass


settings = Settings()
