import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)


class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class PasswordResetRequest(TokenRequest):
    password: str = Field(min_length=12, max_length=256)


class DeleteAccountRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ScanCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    endpoint_url: str = Field(min_length=12, max_length=2048)
    model: str = Field(min_length=1, max_length=120)
    api_key: str = Field(min_length=1, max_length=4096)
    authorized: bool = False

    @field_validator("name", "model")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("This value must not be blank.")
        return stripped


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    target_url: str
    model: str
    status: str
    error_message: str | None
    report: dict[str, Any] | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
