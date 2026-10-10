import json
from datetime import timedelta

from fastapi.testclient import TestClient

from agentshield.service import api, worker
from agentshield.service.database import SessionLocal
from agentshield.service.models import OneTimeToken, Scan, Tenant, User, utcnow


def test_worker_claims_scan_and_erases_api_secret_after_completion(monkeypatch):
    delivered = []
    monkeypatch.setattr(
        api,
        "send_account_email",
        lambda recipient, subject, link, action: delivered.append(
            {"recipient": recipient, "link": link}
        ),
    )
    monkeypatch.setattr(api, "validate_target_url", lambda url: url)
    client = TestClient(api.app)
    client.post(
        "/api/auth/register",
        json={"email": "worker@example.com", "password": "correct horse battery staple"},
    )
    token = delivered[0]["link"].split("verify=", 1)[1]
    client.post("/api/auth/verify-email", json={"token": token})
    access_token = client.post(
        "/api/auth/login",
        json={"email": "worker@example.com", "password": "correct horse battery staple"},
    ).json()["access_token"]
    response = client.post(
        "/api/scans",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "name": "worker-test",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "test-model",
            "api_key": "worker-secret",
            "authorized": True,
        },
    )
    scan_id = response.json()["id"]
    captured = {}

    class FakeTarget:
        def __init__(self, endpoint_url, api_key, model):
            captured["endpoint_url"] = endpoint_url
            captured["api_key"] = api_key
            captured["model"] = model

    class FakeScanner:
        def __init__(self, target):
            self.target = target

        def run_scan(self):
            return {"summary": {"status": "completed"}, "findings": []}

    monkeypatch.setattr(worker, "OpenAICompatibleTarget", FakeTarget)
    monkeypatch.setattr(worker, "AgentScanner", FakeScanner)

    claimed_id = worker.claim_next_scan()
    assert claimed_id == scan_id
    worker.run_scan(scan_id)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "completed"
        assert scan.encrypted_api_key == ""
        assert json.loads(scan.report_json)["summary"]["status"] == "completed"
    assert captured["api_key"] == "worker-secret"
    assert captured["model"] == "test-model"


def test_cleanup_removes_expired_unverified_account_and_workspace():
    now = utcnow()
    with SessionLocal.begin() as db:
        tenant = Tenant(name="Expired workspace")
        user = User(
            tenant_id="",
            email="expired@example.com",
            password_hash="unused",
            is_verified=False,
            created_at=now - timedelta(days=8),
        )
        db.add(tenant)
        db.flush()
        user.tenant_id = tenant.id
        db.add(user)
        db.flush()
        token = OneTimeToken(
            token_hash="a" * 64,
            user_id=user.id,
            purpose="verify",
            expires_at=now + timedelta(days=1),
        )
        db.add(token)
        tenant_id = tenant.id
        user_id = user.id
        token_hash = token.token_hash

    worker.cleanup_expired_records()

    with SessionLocal() as db:
        assert db.get(User, user_id) is None
        assert db.get(Tenant, tenant_id) is None
        assert db.get(OneTimeToken, token_hash) is None
