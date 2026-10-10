import json
import logging
import signal
import time
from datetime import timedelta

from sqlalchemy import delete, select, update

from agentshield.config import get_settings
from agentshield.scanner import AgentScanner
from agentshield.service.database import SessionLocal, initialize_database
from agentshield.service.models import (
    OneTimeToken,
    RateLimitBucket,
    Scan,
    Tenant,
    User,
    utcnow,
)
from agentshield.service.security import decrypt_secret
from agentshield.targets.http_target import OpenAICompatibleTarget

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("agentshield.worker")
_stopping = False
_last_cleanup = 0.0


def _stop(_signum, _frame) -> None:
    global _stopping
    _stopping = True


def claim_next_scan() -> str | None:
    with SessionLocal.begin() as db:
        scan_id = db.scalar(
            select(Scan.id)
            .where(Scan.status == "pending")
            .order_by(Scan.created_at.asc())
            .limit(1)
        )
        if scan_id is None:
            return None
        result = db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == "pending")
            .values(
                status="running",
                attempts=Scan.attempts + 1,
                started_at=utcnow(),
                error_message=None,
            )
        )
        return scan_id if result.rowcount == 1 else None


def recover_stale_scans() -> None:
    settings = get_settings()
    cutoff = utcnow() - timedelta(minutes=30)
    with SessionLocal.begin() as db:
        stale_scans = db.scalars(
            select(Scan).where(
                Scan.status == "running",
                Scan.started_at < cutoff,
            )
        ).all()
        for scan in stale_scans:
            if scan.attempts < settings.scan_max_attempts:
                scan.status = "pending"
                scan.started_at = None
            else:
                scan.status = "failed"
                scan.completed_at = utcnow()
                scan.error_message = "Worker did not complete this scan after retry attempts."
                scan.encrypted_api_key = ""


def cleanup_expired_records() -> None:
    settings = get_settings()
    now = utcnow()
    with SessionLocal.begin() as db:
        db.execute(
            delete(Scan).where(
                Scan.completed_at.is_not(None),
                Scan.completed_at < now - timedelta(days=settings.scan_retention_days),
                Scan.status.in_(("completed", "incomplete", "failed")),
            )
        )
        db.execute(delete(OneTimeToken).where(OneTimeToken.expires_at < now))
        db.execute(
            delete(RateLimitBucket).where(
                RateLimitBucket.window_start < int(time.time()) - 86400
            )
        )
        unverified_cutoff = now - timedelta(
            days=settings.unverified_account_retention_days
        )
        expired_users = select(User.id).where(
            User.is_verified.is_(False), User.created_at < unverified_cutoff
        )
        expired_tenant_ids = db.scalars(
            select(User.tenant_id).where(User.id.in_(expired_users))
        ).all()
        db.execute(delete(OneTimeToken).where(OneTimeToken.user_id.in_(expired_users)))
        db.execute(delete(User).where(User.id.in_(expired_users)))
        if expired_tenant_ids:
            db.execute(delete(Tenant).where(Tenant.id.in_(expired_tenant_ids)))


def run_scan(scan_id: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        try:
            target = OpenAICompatibleTarget(
                endpoint_url=scan.target_url,
                api_key=decrypt_secret(scan.encrypted_api_key),
                model=scan.model,
            )
            report = AgentScanner(target=target).run_scan()
            scan.status = (
                "completed"
                if report["summary"]["status"] == "completed"
                else "incomplete"
            )
            scan.report_json = json.dumps(report, separators=(",", ":"))
            scan.error_message = None
        except Exception:
            logger.exception("Scan %s failed", scan_id)
            settings = get_settings()
            if scan.attempts < settings.scan_max_attempts:
                scan.status = "pending"
                scan.started_at = None
                scan.error_message = "Scan failed and was queued for retry."
            else:
                scan.status = "failed"
                scan.completed_at = utcnow()
                scan.error_message = "Scan failed. Check service logs for diagnostic details."
                scan.encrypted_api_key = ""
        else:
            scan.completed_at = utcnow()
            scan.encrypted_api_key = ""
        db.commit()


def run_worker(once: bool = False) -> None:
    settings = get_settings()
    settings.validate_production()
    if settings.environment != "production":
        initialize_database()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    global _last_cleanup

    while not _stopping:
        recover_stale_scans()
        if time.monotonic() - _last_cleanup >= 3600:
            cleanup_expired_records()
            _last_cleanup = time.monotonic()
        scan_id = claim_next_scan()
        if scan_id is None:
            if once:
                return
            time.sleep(settings.worker_poll_seconds)
            continue
        run_scan(scan_id)
        if once:
            return


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the AgentShield scan worker.")
    parser.add_argument(
        "--once", action="store_true", help="Process one queued scan, if available."
    )
    args = parser.parse_args()
    run_worker(once=args.once)


if __name__ == "__main__":
    main()
