import base64
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from agentshield.service import api
from agentshield.service.database import SessionLocal
from agentshield.service.models import OneTimeToken, Scan, utcnow
from agentshield.service.security import (
    decrypt_secret,
    digest_token,
    encrypt_secret,
    hash_password,
    new_one_time_token,
    verify_password,
)


@pytest.fixture
def client(monkeypatch):
    delivered = []
    monkeypatch.setattr(
        api,
        "send_account_email",
        lambda recipient, subject, link, action: delivered.append(
            {"recipient": recipient, "subject": subject, "link": link}
        ),
    )
    monkeypatch.setattr(api, "validate_target_url", lambda url: url)
    api.initialize_database()
    return TestClient(api.app), delivered


def _verify_account(email: str, delivered: list[dict]) -> str:
    from urllib.parse import urlsplit

    link = next(message["link"] for message in delivered if message["recipient"] == email)
    token = urlsplit(link).fragment.split("=", 1)[1]
    response = TestClient(api.app).post("/api/auth/verify-email", json={"token": token})
    assert response.status_code == 204
    return token


def _register_login(client: TestClient, delivered: list[dict], email: str) -> str:
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": "correct horse battery staple"},
    )
    assert response.status_code == 202
    _verify_account(email, delivered)
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_password_hash_is_salted_and_verified():
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first != second
    assert verify_password(first, "correct horse battery staple")
    assert not verify_password(first, "incorrect password")


def test_target_secrets_are_authenticated_and_encrypted():
    secret = "sk-test-secret-value"
    encrypted = encrypt_secret(secret)

    assert encrypted != secret
    assert decrypt_secret(encrypted) == secret


def test_registration_requires_email_verification_and_login(client):
    http, delivered = client
    response = http.post(
        "/api/auth/register",
        json={"email": " OWNER@EXAMPLE.COM ", "password": "correct horse battery staple"},
    )
    assert response.status_code == 202
    assert delivered[0]["recipient"] == "owner@example.com"
    assert http.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    ).status_code == 403

    _verify_account("owner@example.com", delivered)
    assert http.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    ).status_code == 200


def test_password_reset_revokes_existing_access_tokens(client):
    http, delivered = client
    access_token = _register_login(http, delivered, "reset@example.com")
    headers = {"Authorization": f"Bearer {access_token}"}

    response = http.post(
        "/api/auth/password-reset/request",
        json={"email": "reset@example.com"},
    )
    assert response.status_code == 202
    assert "reset=" in delivered[-1]["link"]
    token = delivered[-1]["link"].split("reset=", 1)[1]
    response = http.post(
        "/api/auth/password-reset/confirm",
        json={"token": token, "password": "a different strong password"},
    )
    assert response.status_code == 204
    assert http.get("/api/me", headers=headers).status_code == 401
    assert http.post(
        "/api/auth/login",
        json={"email": "reset@example.com", "password": "a different strong password"},
    ).status_code == 200


def test_expired_verification_token_is_rejected(client):
    http, delivered = client
    http.post(
        "/api/auth/register",
        json={"email": "expired@example.com", "password": "correct horse battery staple"},
    )
    token = delivered[-1]["link"].split("verify=", 1)[1]
    with SessionLocal.begin() as db:
        one_time = db.get(OneTimeToken, digest_token(token))
        one_time.expires_at = utcnow() - timedelta(seconds=1)

    response = http.post("/api/auth/verify-email", json={"token": token})
    assert response.status_code == 400


def test_scans_are_tenant_isolated_and_credentials_are_not_returned(client):
    http, delivered = client
    owner_token = _register_login(http, delivered, "owner@example.com")
    other_token = _register_login(http, delivered, "other@example.com")
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    other_headers = {"Authorization": f"Bearer {other_token}"}
    response = http.post(
        "/api/scans",
        headers=owner_headers,
        json={
            "name": "staging",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "test-model",
            "api_key": "target-api-secret",
        },
    )
    assert response.status_code == 400
    assert "authorized" in response.json()["detail"]
    response = http.post(
        "/api/scans",
        headers=owner_headers,
        json={
            "name": "staging",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "test-model",
            "api_key": "target-api-secret",
            "authorized": True,
        },
    )
    assert response.status_code == 202
    scan_id = response.json()["id"]
    assert "api_key" not in response.text
    assert http.get("/api/scans", headers=other_headers).json() == []
    assert http.get(f"/api/scans/{scan_id}", headers=other_headers).status_code == 404

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.encrypted_api_key != "target-api-secret"
        assert decrypt_secret(scan.encrypted_api_key) == "target-api-secret"


def test_target_url_validation_rejects_credentials_and_private_hosts(monkeypatch):
    from agentshield.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "environment", "test")
    monkeypatch.setattr(settings, "allowed_target_hosts", "")
    monkeypatch.setattr(settings, "allow_loopback_targets", True)

    from agentshield.service.security import validate_target_url

    assert validate_target_url("http://127.0.0.1:8080/v1/chat/completions")
    with pytest.raises(ValueError, match="Credentials"):
        validate_target_url("https://user:pass@api.example.com/chat")
    monkeypatch.setattr(settings, "allow_loopback_targets", False)
    with pytest.raises(ValueError, match="non-public"):
        validate_target_url("https://127.0.0.1/chat")
    with pytest.raises(ValueError, match="query strings"):
        validate_target_url("https://api.example.com/chat?token=secret")


def test_rate_limited_login_and_unknown_email_responses_are_generic(client):
    http, _delivered = client
    for _ in range(10):
        response = http.post(
            "/api/auth/login",
            json={"email": "absent@example.com", "password": "wrong password"},
        )
        assert response.status_code == 401
    response = http.post(
        "/api/auth/login",
        json={"email": "absent@example.com", "password": "wrong password"},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "300"


def test_email_tokens_are_stored_only_as_hashes():
    token = new_one_time_token()
    assert digest_token(token) != token
    assert len(base64.urlsafe_b64decode(token + "==")) > 16


def test_dashboard_assets_are_served_with_security_headers(client):
    http, _delivered = client

    page = http.get("/")
    script = http.get("/assets/app.js")

    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert script.status_code == 200
    assert "text/javascript" in script.headers["content-type"]


def test_production_configuration_rejects_placeholder_secrets():
    from agentshield.config import Settings

    settings = Settings(
        environment="production",
        database_url=(
            "postgresql+psycopg://agentshield:"
            "a" * 48
            + "@db:5432/agentshield"
        ),
        jwt_secret_key="j" * 48,
        encryption_key="replace-with-a-different-random-secret-at-least-32-characters",
        frontend_url="https://agentshield.example.com",
        allowed_web_hosts="agentshield.example.com",
        allowed_target_hosts="agent-api.example.com",
        smtp_host="smtp.example.com",
        smtp_from_email="agentshield@example.com",
        smtp_password="real-smtp-password",
    )

    with pytest.raises(RuntimeError, match="AGENTSHIELD_ENCRYPTION_KEY"):
        settings.validate_production()


def test_production_configuration_accepts_generated_secrets():
    from agentshield.config import Settings

    password = "p" * 64
    settings = Settings(
        environment="production",
        database_url=f"postgresql+psycopg://agentshield:{password}@db:5432/agentshield",
        jwt_secret_key="j" * 64,
        encryption_key="e" * 64,
        frontend_url="https://agentshield.example.com",
        allowed_web_hosts="agentshield.example.com",
        allowed_target_hosts="agent-api.example.com",
        smtp_host="smtp.example.com",
        smtp_username="agentshield@example.com",
        smtp_password="mail-secret",
        smtp_from_email="agentshield@example.com",
    )

    settings.validate_production()
