import os

os.environ.setdefault("AGENTSHIELD_ENVIRONMENT", "test")
os.environ.setdefault(
    "AGENTSHIELD_DATABASE_URL",
    "sqlite://",
)
os.environ.setdefault("AGENTSHIELD_JWT_SECRET_KEY", "test-secret-key-that-is-long-enough-12345")
os.environ.setdefault("AGENTSHIELD_ENCRYPTION_KEY", "test-encryption-key-that-is-long-enough")
os.environ.setdefault("AGENTSHIELD_FRONTEND_URL", "http://testserver")
os.environ.setdefault("AGENTSHIELD_ALLOWED_TARGET_HOSTS", "api.example.com")
os.environ.setdefault("AGENTSHIELD_ALLOW_LOOPBACK_TARGETS", "true")
os.environ.setdefault("AGENTSHIELD_SMTP_HOST", "localhost")
os.environ.setdefault("AGENTSHIELD_SMTP_FROM_EMAIL", "test@example.com")

import pytest


@pytest.fixture(autouse=True)
def reset_rate_limit_buckets():
    from agentshield.service.database import SessionLocal, initialize_database
    from agentshield.service.models import (
        OneTimeToken,
        RateLimitBucket,
        Scan,
        Tenant,
        User,
    )

    initialize_database()
    with SessionLocal.begin() as db:
        db.query(Scan).delete()
        db.query(OneTimeToken).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.query(RateLimitBucket).delete()
    yield