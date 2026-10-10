from functools import lru_cache
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "production"
    database_url: str = "sqlite:///./agentshield.db"
    jwt_secret_key: str = ""
    encryption_key: str = ""
    access_token_minutes: int = Field(default=20, ge=5, le=60)
    verification_token_hours: int = Field(default=24, ge=1, le=168)
    password_reset_token_minutes: int = Field(default=30, ge=5, le=120)
    frontend_url: str = "http://localhost:8000"
    allowed_web_hosts: str = "localhost,127.0.0.1,testserver"
    allowed_target_hosts: str = ""
    allow_loopback_targets: bool = False
    target_timeout_seconds: float = Field(default=20.0, ge=1.0, le=60.0)
    max_target_response_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    max_active_scans_per_tenant: int = Field(default=2, ge=1, le=20)
    max_scans_per_tenant_per_day: int = Field(default=50, ge=1, le=1000)
    scan_retention_days: int = Field(default=30, ge=1, le=365)
    unverified_account_retention_days: int = Field(default=7, ge=1, le=90)
    scan_max_attempts: int = Field(default=1, ge=1, le=5)
    worker_poll_seconds: float = Field(default=2.0, ge=0.2, le=30.0)
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_starttls: bool = True

    @property
    def target_host_allowlist(self) -> tuple[str, ...]:
        return tuple(
            entry.strip().lower()
            for entry in self.allowed_target_hosts.split(",")
            if entry.strip()
        )

    @property
    def web_host_allowlist(self) -> tuple[str, ...]:
        return tuple(
            entry.strip()
            for entry in self.allowed_web_hosts.split(",")
            if entry.strip()
        )

    def validate_production(self) -> None:
        if self.environment != "production":
            return
        secrets_to_check = {
            "AGENTSHIELD_JWT_SECRET_KEY": self.jwt_secret_key,
            "AGENTSHIELD_ENCRYPTION_KEY": self.encryption_key,
            "POSTGRES_PASSWORD": self.database_url.rsplit("@", 1)[0].rsplit(":", 1)[-1],
        }
        if self.jwt_secret_key == self.encryption_key:
            raise RuntimeError("JWT and encryption secrets must be different.")
        if not self.database_url.startswith(("postgresql://", "postgresql+")):
            raise RuntimeError("Production deployments must use PostgreSQL.")
        for name, value in secrets_to_check.items():
            if len(value) < 48 or value.strip().lower().startswith(
                ("replace-", "change-", "your-")
            ):
                raise RuntimeError(f"{name} must be a generated secret of at least 48 characters.")
        if not self.smtp_host or not self.smtp_from_email:
            raise RuntimeError("Production deployments require SMTP_HOST and SMTP_FROM_EMAIL.")
        if not self.smtp_starttls:
            raise RuntimeError("Production SMTP connections must use STARTTLS.")
        if not self.frontend_url.startswith("https://"):
            raise RuntimeError("Production account links must use HTTPS.")
        frontend = urlsplit(self.frontend_url)
        if (
            not frontend.hostname
            or frontend.path not in {"", "/"}
            or frontend.query
            or frontend.fragment
        ):
            raise RuntimeError("AGENTSHIELD_FRONTEND_URL must be an HTTPS origin.")
        if not self.target_host_allowlist:
            raise RuntimeError(
                "Production deployments must configure AGENTSHIELD_ALLOWED_TARGET_HOSTS."
            )
        for host in self.target_host_allowlist:
            hostname = host[2:] if host.startswith("*.") else host
            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",
                hostname,
            ) or ".." in hostname:
                raise RuntimeError(
                    "Allowed target hosts must be DNS hostnames, not URLs, IPs, or ports."
                )
        if not self.web_host_allowlist or "*" in self.web_host_allowlist:
            raise RuntimeError("Production deployments require explicit allowed web hosts.")
        if frontend.hostname.lower() not in {
            host.lower() for host in self.web_host_allowlist
        }:
            raise RuntimeError(
                "AGENTSHIELD_FRONTEND_URL host must be in AGENTSHIELD_ALLOWED_WEB_HOSTS."
            )
        for host in self.web_host_allowlist:
            if not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or ".." in host:
                raise RuntimeError(
                    "Allowed web hosts must be hostnames, not URLs or wildcard patterns."
                )
        if self.smtp_username and not self.smtp_password:
            raise RuntimeError("SMTP_PASSWORD is required when SMTP_USERNAME is configured.")
        if self.smtp_password.strip().lower().startswith(("replace-", "change-", "your-")):
            raise RuntimeError("SMTP_PASSWORD must be set to a real secret.")


@lru_cache
def get_settings() -> Settings:
    return Settings()